#pragma once

#include <string>
#include <vector>

#include "core/core.h"

namespace abyss::git {

// Generic, campaign-independent detector for the "clock manipulation ->
// identity/metadata spoofing -> commit amend -> force-push" Git propagation
// TTP documented across PolinRider-family incidents: a batch/shell/
// PowerShell script that reads the previous commit's metadata, saves and
// manipulates the system clock, optionally rewrites the Git author/
// committer identity, stages changes, amends a commit (usually with
// --no-verify), restores the clock, and force-pushes. See
// README.md and README.md for the full signal model
// and scoring rationale. Looks at script content only (any filename) —
// known artifact *filenames* for specific campaigns (e.g. PolinRider's
// temp_auto_push.bat) belong in rules/campaigns/*.rules as IOC rules, not
// here, so this engine stays campaign-independent. No git operations are
// performed here — this is static text analysis only.
std::vector<Finding> scanGitPropagationArtifacts(const std::string& relPath, const std::string& filename,
                                                  const std::string& extensionLower,
                                                  const std::string& content);

// Detects a `.gitignore` that has been used to hide known propagation
// artifact filenames from `git status` — a corroborating pattern
// documented in the sam1am/anyapk#64 incident disclosure (the malicious
// commit added temp_auto_push.bat/temp_interactive_push.bat to
// .gitignore). Only applies to files literally named ".gitignore".
std::vector<Finding> scanGitignoreForHiddenArtifacts(const std::string& relPath, const std::string& filename,
                                                      const std::string& content);

} // namespace abyss::git
