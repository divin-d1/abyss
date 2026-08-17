#pragma once

#include <chrono>
#include <string>
#include <vector>

namespace abyss::git {

struct ProcessResult {
    bool started = false;
    bool timedOut = false;
    int exitCode = -1;
    std::string output;
    std::string error;
};

// Executes git directly, never through cmd.exe/PowerShell/a shell. Arguments
// are passed as individual values and output is bounded.
ProcessResult runGit(const std::string& workingDirectory,
                     const std::vector<std::string>& arguments,
                     std::chrono::seconds timeout = std::chrono::seconds(180),
                     std::size_t maxOutputBytes = 8 * 1024 * 1024);

bool remoteUrlAllowed(const std::string& remote, std::string& error);
bool repositoryConfigSafe(const std::string& repository, std::string& error);

struct StagedOperation {
    bool ok = false;
    std::string stagePath;
    std::string targetRef;
    // For preparePull specifically: the exact commit SHA targetRef resolved
    // to at staging time. finalizePull merges to this SHA, not the
    // symbolic ref name — the ref (e.g. "origin/main") can move between
    // when staging/scanning happens and when finalizePull runs (another
    // fetch, a concurrent operation), and merging by the symbolic name
    // would then fast-forward to different, unscanned content. Empty for
    // operations other than pull.
    std::string resolvedSha;
    std::string output;
    std::string error;
};

// Clone is staged under a sibling directory with checkout hooks disabled.
// The caller must scan stagePath and call finalizeClone.
StagedOperation prepareClone(const std::string& remote,
                             const std::string& destination);
bool finalizeClone(const StagedOperation& operation,
                   const std::string& destination,
                   bool allow,
                   std::string& message);

// Pull is fetch + detached worktree staging. The current branch is not
// changed until the caller scans stagePath and calls finalizePull.
StagedOperation preparePull(const std::string& repository);
bool finalizePull(const std::string& repository,
                  const StagedOperation& operation,
                  bool allow,
                  std::string& message);

ProcessResult timeline(const std::string& repository, std::size_t limit = 200);
ProcessResult graph(const std::string& repository, std::size_t limit = 200);

// Materializes a user-selected commit in a detached recovery worktree. It
// never rewrites the current branch or remote history.
StagedOperation prepareRecovery(const std::string& repository,
                                const std::string& commit,
                                const std::string& destination);

} // namespace abyss::git
