#pragma once

#include <string>
#include <vector>

#include "core/core.h"

namespace abyss::vscode {

// Statically parses a `.vscode/tasks.json` (JSONC) file as inert data and
// flags risky automation patterns. Never activates or runs any task.
//
// Beyond the direct case, this follows `dependsOn` task-dependency graphs
// (cycle- and depth-bounded), platform-specific `windows`/`linux`/`osx`
// command overrides, and `options.shell` — because a `folderOpen` task can
// carry no command of its own and instead delegate execution to another
// task by label, or hide the real payload behind a platform override that
// only applies on the victim's actual OS. See README.md.
std::vector<Finding> scanTasksJson(const std::string& relPath, const std::string& content);

// Statically parses a `*.code-workspace` file (JSONC), which may embed a
// `tasks` object with the same schema as tasks.json. Delegates to the same
// evaluation logic as scanTasksJson.
std::vector<Finding> scanCodeWorkspace(const std::string& relPath, const std::string& content);

// One installed VS Code extension's statically-read metadata (section 31).
// Only `package.json` is parsed as data; the extension is never activated.
struct ExtensionRecord {
    std::string id;           // "<publisher>.<name>"
    std::string publisher;
    std::string name;
    std::string version;
    std::string path;
    std::string main;
    std::string browser;
    std::vector<std::string> activationEvents;
    std::vector<std::string> extensionDependencies;
    std::vector<std::string> dependencies; // dependency package names only
    std::vector<std::string> contributesKeys;
    std::string manifestSha256;
};

// Discovers installed extensions under the given VS Code extensions root
// (typically `%USERPROFILE%\.vscode\extensions`). Reads each `package.json`
// as data only. A malformed manifest is skipped (never crashes the scan);
// see README.md for the "fails safely" contract.
std::vector<ExtensionRecord> discoverExtensions(const std::string& extensionsRoot);

// Returns VS Code's default per-user extensions directory on this host
// (`%USERPROFILE%\.vscode\extensions`), or an empty string if it cannot be
// determined.
std::string defaultExtensionsRoot();

// Static manifest-shape risk check for one installed extension: broad
// unconditional activation (`activationEvents: ["*"]`) combined with no
// declared contribution points, and an entry point (`main`/`browser`) that
// attempts to escape the extension's own directory. This is "exact
// attribution" only — it identifies *which extension's manifest* looks
// unusual, not that the extension actually did anything at runtime.
// Extension-host process lineage and workspace-time correlation require
// the ETW runtime milestone and are not implemented here — see
// README.md. Findings use `f.filePath = "vscode-extension:<id>"`
// since these aren't findings about a scanned repository file.
std::vector<Finding> scanExtensionRecord(const ExtensionRecord& ext);

} // namespace abyss::vscode
