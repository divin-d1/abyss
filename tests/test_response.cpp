#include "test_harness.h"

#include <filesystem>
#include <fstream>

#include "response/response.h"

using namespace abyss;
namespace fs = std::filesystem;

namespace {
fs::path responseTemp(const std::string& name) {
    return fs::temp_directory_path() / ("abyss_response_test_" + name);
}

void reset(const fs::path& path) {
    std::error_code ec;
    fs::remove_all(path, ec);
    fs::create_directories(path, ec);
}
}

ABYSS_TEST("response: unconfirmed remediation never changes a file") {
    fs::path base = responseTemp("dry_run"); reset(base);
    fs::path root = base / "repo"; fs::create_directories(root);
    std::ofstream(root / "bad.js") << "global['_V']='A9-6187'";
    Finding f; f.findingId="F1"; f.ruleId="test.confirmed"; f.filePath="bad.js";
    f.severity=Severity::Critical; f.confidence=Confidence::Confirmed; f.description="test";
    auto plan = response::buildPlan(root.string(), {f});
    auto result = response::applyPlan(plan, (base / "state").string(), false);
    ABYSS_CHECK(fs::exists(root / "bad.js"));
    ABYSS_CHECK(result.quarantined.empty());
    ABYSS_CHECK(!result.errors.empty());
    std::error_code ec; fs::remove_all(base, ec);
}

ABYSS_TEST("response: confirmed file is hash-verified, quarantined, listed, and restored") {
    fs::path base = responseTemp("roundtrip"); reset(base);
    fs::path root = base / "repo"; fs::create_directories(root);
    const std::string original = "confirmed malicious test bytes";
    std::ofstream(root / "bad.js", std::ios::binary) << original;
    Finding f; f.findingId="F2"; f.ruleId="test.confirmed"; f.filePath="bad.js";
    f.severity=Severity::Critical; f.confidence=Confidence::Confirmed; f.description="test quarantine";
    auto plan = response::buildPlan(root.string(), {f});
    ABYSS_CHECK(plan.actions.size() == 1 && plan.actions[0].eligible);
    const std::string state = (base / "state").string();
    auto result = response::applyPlan(plan, state, true);
    ABYSS_CHECK(result.errors.empty());
    ABYSS_CHECK(result.quarantined.size() == 1);
    ABYSS_CHECK(!fs::exists(root / "bad.js"));
    auto records = response::listQuarantine(state);
    ABYSS_CHECK(records.size() == 1 && !records[0].restored);
    std::string error;
    ABYSS_CHECK(response::restoreQuarantine(state, records[0].id, false, error));
    ABYSS_CHECK(fs::exists(root / "bad.js"));
    std::ifstream in(root / "bad.js", std::ios::binary); std::string restored((std::istreambuf_iterator<char>(in)), {});
    ABYSS_CHECK(restored == original);
    records = response::listQuarantine(state);
    ABYSS_CHECK(records.size() == 1 && records[0].restored);
    std::error_code ec; fs::remove_all(base, ec);
}

ABYSS_TEST("response: non-confirmed and out-of-root findings stay review-only") {
    fs::path base = responseTemp("eligibility"); reset(base);
    fs::path root = base / "repo"; fs::create_directories(root);
    std::ofstream(root / "review.js") << "review";
    Finding review; review.findingId="F3"; review.ruleId="test.review"; review.filePath="review.js";
    review.severity=Severity::Critical; review.confidence=Confidence::High;
    Finding escape = review; escape.findingId="F4"; escape.confidence=Confidence::Confirmed; escape.filePath="../outside.js";
    auto plan = response::buildPlan(root.string(), {review, escape});
    ABYSS_CHECK(plan.actions.size() == 2);
    ABYSS_CHECK(!plan.actions[0].eligible);
    ABYSS_CHECK(!plan.actions[1].eligible);
    std::error_code ec; fs::remove_all(base, ec);
}

ABYSS_TEST("response: protected-root state round-trips without duplicates") {
    fs::path base = responseTemp("protected"); reset(base);
    fs::path repo = base / "repo"; fs::create_directories(repo);
    std::string error;
    ABYSS_CHECK(response::addProtectedRoot((base / "state").string(), repo.string(), error));
    ABYSS_CHECK(response::addProtectedRoot((base / "state").string(), repo.string(), error));
    auto roots = response::protectedRoots((base / "state").string());
    ABYSS_CHECK(roots.size() == 1);
    ABYSS_CHECK(response::removeProtectedRoot((base / "state").string(), repo.string(), error));
    ABYSS_CHECK(response::protectedRoots((base / "state").string()).empty());
    std::error_code ec; fs::remove_all(base, ec);
}

ABYSS_TEST("response: repository guards preserve an existing hook") {
    fs::path base = responseTemp("hooks"); reset(base);
    fs::create_directories(base / "repo" / ".git" / "hooks");
    std::ofstream(base / "repo" / ".git" / "hooks" / "pre-commit") << "existing";
    std::vector<std::string> messages; std::string error;
    ABYSS_CHECK(response::installRepositoryGuards((base / "repo").string(), "C:/Abyss/abyss.exe", messages, error));
    std::ifstream in(base / "repo" / ".git" / "hooks" / "pre-commit"); std::string text((std::istreambuf_iterator<char>(in)), {});
    ABYSS_CHECK(text == "existing");
    ABYSS_CHECK(fs::exists(base / "repo" / ".git" / "hooks" / "pre-push"));
    messages.clear();
    ABYSS_CHECK(response::removeRepositoryGuards((base / "repo").string(), "C:/Abyss/abyss.exe", messages, error));
    ABYSS_CHECK(fs::exists(base / "repo" / ".git" / "hooks" / "pre-commit"));
    ABYSS_CHECK(!fs::exists(base / "repo" / ".git" / "hooks" / "pre-push"));
    std::error_code ec; fs::remove_all(base, ec);
}

ABYSS_TEST("response: inspectPersistence runs against the real machine without crashing") {
    // Previously zero test coverage at all for this function or
    // discoverHostTargets -- both are heavy, Windows-API-specific code
    // (registry enumeration, service/process/network table walking) that
    // only ever ran for the first time when a user actually chose
    // "system-scan", which is exactly how a real stack-buffer-overrun
    // crash (0xc0000409) reached a release build undetected.
    auto findings = response::inspectPersistence();
    // No assertion on the content -- this machine's actual Run keys,
    // services, and processes are unknown and not this test's business.
    // Reaching this line at all, repeatedly, without the /GS check firing
    // is the actual regression coverage.
    (void)findings;
}

ABYSS_TEST("response: inspectPersistence is safe to call many times in a row") {
    for (int i = 0; i < 25; ++i) {
        auto findings = response::inspectPersistence();
        (void)findings;
    }
}

ABYSS_TEST("response: discoverHostTargets runs against the real machine without crashing") {
    // Bounded small so this stays fast in CI while still exercising the
    // real drive-enumeration and directory-walk code paths.
    auto discovery = response::discoverHostTargets(/*maxDepth=*/2, /*maxDirectories=*/500);
    (void)discovery;
}
