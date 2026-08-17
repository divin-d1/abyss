#include "test_harness.h"

#include <algorithm>

#include "vscode/vscode.h"

using namespace abyss;
using namespace abyss::test;

namespace {
bool hasRule(const std::vector<Finding>& findings, const std::string& ruleId) {
    return std::any_of(findings.begin(), findings.end(), [&](const Finding& f) { return f.ruleId == ruleId; });
}
const Finding* findByRule(const std::vector<Finding>& findings, const std::string& ruleId) {
    auto it = std::find_if(findings.begin(), findings.end(), [&](const Finding& f) { return f.ruleId == ruleId; });
    return it == findings.end() ? nullptr : &*it;
}
} // namespace

ABYSS_TEST("vscode tasks: hidden folderOpen task executing an asset is Critical") {
    std::string content = readFixtureText("vscode-tasks-folderopen-hidden.json.sample");
    auto findings = vscode::scanTasksJson(".vscode/tasks.json", content);
    ABYSS_CHECK(hasRule(findings, "core.vscode_folderopen_execution_surface"));
    ABYSS_CHECK(hasRule(findings, "core.vscode_task_asset_as_executable"));
    const auto* f = findByRule(findings, "core.vscode_folderopen_execution_surface");
    if (f) ABYSS_CHECK(f->severity == Severity::Critical);
}

ABYSS_TEST("vscode tasks: visible folderOpen task with a benign command is Low severity, not silent") {
    // Per the explicit requirement that visibility reduces suspicion but
    // does not remove execution risk: a visible folderOpen task still
    // produces a finding, just at Low severity/confidence rather than
    // Critical — distinct from the empty-findings case below.
    std::string content = readFixtureText("vscode-tasks-folderopen-legit.json.sample");
    auto findings = vscode::scanTasksJson(".vscode/tasks.json", content);
    ABYSS_CHECK(hasRule(findings, "core.vscode_folderopen_execution_surface"));
    const auto* f = findByRule(findings, "core.vscode_folderopen_execution_surface");
    if (f) {
        ABYSS_CHECK(f->severity == Severity::Low);
        ABYSS_CHECK(f->confidence == Confidence::Low);
    }
    ABYSS_CHECK(!hasRule(findings, "core.vscode_task_asset_as_executable"));
    ABYSS_CHECK(!hasRule(findings, "core.vscode_task_download_and_execute"));
}

ABYSS_TEST("vscode tasks: a folderOpen task with no execution content at all produces no finding") {
    std::string content = R"({
        "version": "2.0.0",
        "tasks": [ { "label": "noop", "runOptions": { "runOn": "folderOpen" } } ]
    })";
    auto findings = vscode::scanTasksJson(".vscode/tasks.json", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("vscode tasks: 'echo font.woff2' (label/command, no interpreter) is not a fake-asset finding") {
    std::string content = R"({
        "version": "2.0.0",
        "tasks": [
            {
                "label": "echo font.woff2",
                "type": "shell",
                "command": "echo",
                "args": ["font.woff2"],
                "runOptions": { "runOn": "folderOpen" }
            }
        ]
    })";
    auto findings = vscode::scanTasksJson(".vscode/tasks.json", content);
    ABYSS_CHECK(!hasRule(findings, "core.vscode_task_asset_as_executable"));
}

ABYSS_TEST("vscode tasks: a path containing 'node_modules' does not false-positive as node execution") {
    std::string content = R"({
        "version": "2.0.0",
        "tasks": [
            {
                "label": "lint",
                "type": "shell",
                "command": "./node_modules/.bin/eslint",
                "args": ["."],
                "runOptions": { "runOn": "folderOpen" },
                "presentation": { "reveal": "silent" }
            }
        ]
    })";
    auto findings = vscode::scanTasksJson(".vscode/tasks.json", content);
    // Still a hidden folderOpen execution surface (real risk), but must
    // NOT be classified as "interpreter" execution via a substring match
    // on "node" inside "node_modules" -- so neither the asset-execution
    // nor download-and-execute findings (which require a real interpreter
    // token) should fire here.
    ABYSS_CHECK(!hasRule(findings, "core.vscode_task_asset_as_executable"));
    ABYSS_CHECK(!hasRule(findings, "core.vscode_task_download_and_execute"));
}

ABYSS_TEST("vscode tasks: 'node font.woff2' (real interpreter + asset arg) is a fake-asset finding") {
    std::string content = R"({
        "version": "2.0.0",
        "tasks": [
            {
                "label": "init",
                "type": "shell",
                "command": "node",
                "args": ["font.woff2"],
                "runOptions": { "runOn": "folderOpen" }
            }
        ]
    })";
    auto findings = vscode::scanTasksJson(".vscode/tasks.json", content);
    ABYSS_CHECK(hasRule(findings, "core.vscode_task_asset_as_executable"));
}

ABYSS_TEST("vscode tasks: dependsOn chain resolves to the real executing task") {
    // The folderOpen task itself has no command — it only orchestrates via
    // dependsOn. The actual hidden node-on-a-font execution lives in the
    // dependency, which must still be caught.
    std::string content = R"({
        "version": "2.0.0",
        "tasks": [
            {
                "label": "bootstrap",
                "dependsOn": ["real work"],
                "runOptions": { "runOn": "folderOpen" },
                "presentation": { "reveal": "silent" }
            },
            {
                "label": "real work",
                "type": "shell",
                "command": "node",
                "args": ["public/fonts/fa-solid-400.woff2"]
            }
        ]
    })";
    auto findings = vscode::scanTasksJson(".vscode/tasks.json", content);
    ABYSS_CHECK(hasRule(findings, "core.vscode_task_asset_as_executable"));
    const auto* f = findByRule(findings, "core.vscode_folderopen_execution_surface");
    ABYSS_CHECK(f != nullptr);
    if (f) ABYSS_CHECK(f->severity == Severity::Critical);
}

ABYSS_TEST("vscode tasks: a cyclic dependsOn graph does not hang the scan") {
    std::string content = R"({
        "version": "2.0.0",
        "tasks": [
            { "label": "a", "dependsOn": ["b"], "runOptions": { "runOn": "folderOpen" } },
            { "label": "b", "dependsOn": ["a"], "command": "node", "args": ["x.woff2"] }
        ]
    })";
    auto findings = vscode::scanTasksJson(".vscode/tasks.json", content);
    // Reaching this line at all (rather than hanging/crashing) is the point
    // of the test; it should still resolve through the cycle to find "b".
    ABYSS_CHECK(hasRule(findings, "core.vscode_task_asset_as_executable"));
}

ABYSS_TEST("vscode tasks: a platform-specific 'windows' override is inspected") {
    std::string content = R"({
        "version": "2.0.0",
        "tasks": [
            {
                "label": "setup",
                "command": "echo",
                "args": ["ok"],
                "windows": { "command": "node", "args": ["fake-font.woff2"] },
                "runOptions": { "runOn": "folderOpen" },
                "presentation": { "reveal": "silent" }
            }
        ]
    })";
    auto findings = vscode::scanTasksJson(".vscode/tasks.json", content);
    ABYSS_CHECK(hasRule(findings, "core.vscode_task_asset_as_executable"));
}

ABYSS_TEST("vscode tasks: options.shell.executable is inspected") {
    std::string content = R"({
        "version": "2.0.0",
        "tasks": [
            {
                "label": "custom-shell",
                "type": "shell",
                "command": "./run.woff2",
                "options": { "shell": { "executable": "node" } },
                "runOptions": { "runOn": "folderOpen" },
                "presentation": { "reveal": "silent" }
            }
        ]
    })";
    auto findings = vscode::scanTasksJson(".vscode/tasks.json", content);
    ABYSS_CHECK(hasRule(findings, "core.vscode_task_asset_as_executable"));
}

ABYSS_TEST("vscode tasks: malformed JSON does not crash and yields no findings") {
    auto findings = vscode::scanTasksJson(".vscode/tasks.json", "{ not valid json");
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST(".code-workspace: embedded tasks are evaluated the same as tasks.json") {
    std::string content = R"({
        "folders": [ { "path": "." } ],
        "tasks": {
            "version": "2.0.0",
            "tasks": [
                {
                    "label": "init",
                    "command": "node",
                    "args": ["fonts/fake.woff2"],
                    "runOptions": { "runOn": "folderOpen" },
                    "presentation": { "reveal": "silent" }
                }
            ]
        }
    })";
    auto findings = vscode::scanCodeWorkspace("project.code-workspace", content);
    ABYSS_CHECK(hasRule(findings, "core.vscode_task_asset_as_executable"));
}

ABYSS_TEST(".code-workspace: a workspace with no tasks produces no findings") {
    std::string content = R"({ "folders": [ { "path": "." } ], "settings": {} })";
    auto findings = vscode::scanCodeWorkspace("project.code-workspace", content);
    ABYSS_CHECK(findings.empty());
}

ABYSS_TEST("extension record: broad activation with no contribution is flagged") {
    vscode::ExtensionRecord ext;
    ext.id = "evil.publisher";
    ext.activationEvents = {"*"};
    ext.contributesKeys = {};
    auto findings = vscode::scanExtensionRecord(ext);
    ABYSS_CHECK(hasRule(findings, "core.vscode_extension_broad_activation_no_contribution"));
}

ABYSS_TEST("extension record: broad activation WITH a real contribution is not flagged") {
    vscode::ExtensionRecord ext;
    ext.id = "ms-python.python";
    ext.activationEvents = {"*"};
    ext.contributesKeys = {"commands", "languages", "configuration"};
    auto findings = vscode::scanExtensionRecord(ext);
    ABYSS_CHECK(!hasRule(findings, "core.vscode_extension_broad_activation_no_contribution"));
}

ABYSS_TEST("extension record: entry point path traversal is flagged") {
    vscode::ExtensionRecord ext;
    ext.id = "some.extension";
    ext.main = "../../../../windows/system32/evil.js";
    auto findings = vscode::scanExtensionRecord(ext);
    ABYSS_CHECK(hasRule(findings, "core.vscode_extension_entrypoint_traversal"));
}

ABYSS_TEST("extension record: a normal manifest produces no findings") {
    vscode::ExtensionRecord ext;
    ext.id = "publisher.normal-extension";
    ext.main = "./out/extension.js";
    ext.activationEvents = {"onLanguage:javascript"};
    ext.contributesKeys = {"commands"};
    auto findings = vscode::scanExtensionRecord(ext);
    ABYSS_CHECK(findings.empty());
}
