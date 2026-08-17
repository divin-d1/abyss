#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

#include "core/core.h"

namespace abyss::response {

struct HostTarget {
    std::string path;
    std::string kind; // repository | developer-root | persistence-file
};

struct HostDiscovery {
    std::vector<HostTarget> targets;
    std::vector<std::string> errors;
    std::size_t directoriesVisited = 0;
};

// Finds developer repositories without reading repository-controlled code.
// The walk is bounded by depth and directory count so a system scan cannot
// accidentally consume an entire workstation indefinitely. This walk is a
// single sequential directory-metadata traversal (find the repos), separate
// from the per-repository file scan that follows it (which does run
// multithreaded -- see scanner::scanRepository). More threads do not
// meaningfully speed up one directory tree's metadata walk against one
// physical disk, so onProgress exists to make this phase visibly alive
// (called throughout the walk with the running directory count) rather
// than to make it faster: without it, a scan of a real machine's whole
// directory tree can run for a while with zero output, which looks
// indistinguishable from a hang.
HostDiscovery discoverHostTargets(std::size_t maxDepth = 7,
                                  std::size_t maxDirectories = 250000,
                                  std::function<void(std::size_t directoriesVisited)> onProgress = {});

// Inspects native Windows persistence locations as data. On other platforms
// this returns an empty list; the public release target is Windows 10/11.
std::vector<Finding> inspectPersistence();

struct QuarantineRecord {
    std::string id;
    std::string originalPath;
    std::string storedPath;
    std::string sha256;
    std::string ruleId;
    std::string reason;
    bool restored = false;
};

struct RemediationAction {
    std::string findingId;
    std::string ruleId;
    std::string sourcePath;
    std::string reason;
    bool eligible = false;
    std::string refusal;
};

struct RemediationPlan {
    std::string scanRoot;
    std::vector<RemediationAction> actions;
};

struct RemediationResult {
    std::vector<QuarantineRecord> quarantined;
    std::vector<std::string> skipped;
    std::vector<std::string> errors;
};

std::string defaultStateRoot();

// Only Critical + Confirmed file findings are eligible for automated
// quarantine. Everything else remains review-only.
RemediationPlan buildPlan(const std::string& scanRoot,
                          const std::vector<Finding>& findings);

// Applies a plan only when confirmed=true. Files are copied, hash-verified,
// journaled, and then removed from the active location. The protected copy is
// never deleted by remediation and can be restored later.
RemediationResult applyPlan(const RemediationPlan& plan,
                            const std::string& stateRoot,
                            bool confirmed);

std::vector<QuarantineRecord> listQuarantine(const std::string& stateRoot,
                                             std::vector<std::string>* errors = nullptr);

bool restoreQuarantine(const std::string& stateRoot,
                       const std::string& id,
                       bool overwrite,
                       std::string& error);

// Local protection configuration. These functions only manage trusted state;
// service installation and the monitoring loop are owned by the CLI.
bool addProtectedRoot(const std::string& stateRoot, const std::string& root,
                      std::string& error);
bool removeProtectedRoot(const std::string& stateRoot, const std::string& root,
                         std::string& error);
std::vector<std::string> protectedRoots(const std::string& stateRoot,
                                        std::vector<std::string>* errors = nullptr);

// Installs non-destructive repository hooks that block commits/pushes when
// preflight fails. Existing hooks are never overwritten.
bool installRepositoryGuards(const std::string& repository,
                             const std::string& abyssExecutable,
                             std::vector<std::string>& messages,
                             std::string& error);
bool removeRepositoryGuards(const std::string& repository,
                            const std::string& abyssExecutable,
                            std::vector<std::string>& messages,
                            std::string& error);

} // namespace abyss::response
