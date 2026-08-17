#include "test_harness.h"

#include <filesystem>
#include <fstream>

#include "git/safe_git.h"

namespace fs = std::filesystem;

ABYSS_TEST("safe git: remote policy blocks local and helper transports") {
    std::string error;
    ABYSS_CHECK(abyss::git::remoteUrlAllowed("https://github.com/example/repo.git", error));
    ABYSS_CHECK(abyss::git::remoteUrlAllowed("git@github.com:example/repo.git", error));
    ABYSS_CHECK(!abyss::git::remoteUrlAllowed("file:///tmp/repo", error));
    ABYSS_CHECK(!abyss::git::remoteUrlAllowed("ext::sh -c payload", error));
}

ABYSS_TEST("safe git: direct runner invokes git without a shell") {
    auto result = abyss::git::runGit(fs::current_path().string(), {"--version"});
    ABYSS_CHECK(result.started);
    ABYSS_CHECK(!result.timedOut);
    ABYSS_CHECK(result.exitCode == 0);
    ABYSS_CHECK(result.output.find("git version") != std::string::npos);
}

ABYSS_TEST("safe git: executable local filters make repository configuration unsafe") {
    fs::path base = fs::temp_directory_path() / "abyss_safe_git_config_test";
    std::error_code ec; fs::remove_all(base, ec); fs::create_directories(base / ".git");
    std::ofstream(base / ".git" / "config") << "[core]\nrepositoryformatversion = 0\n[filter \"x\"]\nsmudge = powershell payload\n";
    std::string error;
    ABYSS_CHECK(!abyss::git::repositoryConfigSafe(base.string(), error));
    std::ofstream(base / ".git" / "config", std::ios::trunc) << "[core]\nrepositoryformatversion = 0\n";
    ABYSS_CHECK(abyss::git::repositoryConfigSafe(base.string(), error));
    fs::remove_all(base, ec);
}

ABYSS_TEST("safe git: non-standard whitespace around the filter assignment does not evade detection") {
    // Regression: git config syntax allows "smudge=cmd" (no spaces) and
    // "smudge  =  cmd" (extra spaces) as equivalent to "smudge = cmd" -- a
    // fixed-string check for exactly one space each side missed both.
    fs::path base = fs::temp_directory_path() / "abyss_safe_git_config_whitespace_test";
    std::error_code ec; fs::remove_all(base, ec); fs::create_directories(base / ".git");
    std::string error;

    std::ofstream(base / ".git" / "config") << "[filter \"x\"]\nsmudge=powershell payload\n";
    ABYSS_CHECK(!abyss::git::repositoryConfigSafe(base.string(), error));

    std::ofstream(base / ".git" / "config", std::ios::trunc) << "[filter \"x\"]\nsmudge   =   powershell payload\n";
    ABYSS_CHECK(!abyss::git::repositoryConfigSafe(base.string(), error));

    fs::remove_all(base, ec);
}

namespace {
bool runOk(const std::string& cwd, const std::vector<std::string>& args) {
    auto result = abyss::git::runGit(cwd, args);
    return result.started && !result.timedOut && result.exitCode == 0;
}
}

ABYSS_TEST("safe pull: merges the exact commit that was staged, even if the upstream ref moves after") {
    // Regression: finalizePull used to merge by symbolic ref name
    // ("origin/main"), which is re-resolved at merge time -- if the ref
    // moved between staging/scanning and finalizing, the merge could apply
    // different, unscanned content. preparePull now pins a concrete SHA at
    // staging time and finalizePull merges that SHA specifically.
    namespace fs = std::filesystem;
    fs::path base = fs::temp_directory_path() / "abyss_test_safe_pull_sha_pin";
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::create_directories(base / "remote", ec);
    fs::create_directories(base / "local", ec);
    std::string remote = (base / "remote").string();
    std::string local = (base / "local").string();

    bool setupOk = runOk(remote, {"init", "-q"}) &&
                   runOk(remote, {"config", "user.email", "t@example.com"}) &&
                   runOk(remote, {"config", "user.name", "Test"});
    if (setupOk) {
        std::ofstream(base / "remote" / "a.txt") << "first\n";
        setupOk = runOk(remote, {"add", "a.txt"}) && runOk(remote, {"commit", "-q", "-m", "first"});
    }
    setupOk = setupOk && runOk(base.string(), {"clone", "-q", remote, local});
    if (setupOk) {
        setupOk = runOk(local, {"config", "user.email", "t@example.com"}) &&
                  runOk(local, {"config", "user.name", "Test"});
    }
    if (!setupOk) {
        // Environment couldn't set up a local git fixture (no git on PATH
        // for the test process, or similar) -- not something this test
        // should fail the suite over.
        fs::remove_all(base, ec);
        return;
    }

    // Advance the remote by one commit -- this is what preparePull should
    // fetch and stage.
    std::ofstream(base / "remote" / "b.txt") << "second\n";
    ABYSS_CHECK(runOk(remote, {"add", "b.txt"}));
    ABYSS_CHECK(runOk(remote, {"commit", "-q", "-m", "second"}));
    auto expectedSha = abyss::git::runGit(remote, {"rev-parse", "HEAD"});
    std::string expected = expectedSha.output;
    while (!expected.empty() && (expected.back() == '\r' || expected.back() == '\n')) expected.pop_back();

    auto staged = abyss::git::preparePull(local);
    ABYSS_CHECK(staged.ok);
    ABYSS_CHECK(staged.resolvedSha == expected);
    ABYSS_CHECK(staged.resolvedSha.size() == 40);

    // Simulate the ref moving *after* staging but *before* finalizing: a
    // third commit lands on the remote and gets fetched into the local
    // tracking ref, all before finalizePull runs.
    std::ofstream(base / "remote" / "c.txt") << "third\n";
    ABYSS_CHECK(runOk(remote, {"add", "c.txt"}));
    ABYSS_CHECK(runOk(remote, {"commit", "-q", "-m", "third"}));
    ABYSS_CHECK(runOk(local, {"fetch", "-q", "origin"}));

    std::string message;
    ABYSS_CHECK(abyss::git::finalizePull(local, staged, true, message));
    auto localHead = abyss::git::runGit(local, {"rev-parse", "HEAD"});
    std::string localHeadStr = localHead.output;
    while (!localHeadStr.empty() && (localHeadStr.back() == '\r' || localHeadStr.back() == '\n')) localHeadStr.pop_back();
    // Must land on exactly the commit that was staged and scanned -- not
    // the newer "third" commit that arrived after staging.
    ABYSS_CHECK(localHeadStr == expected);

    fs::remove_all(base, ec);
}
