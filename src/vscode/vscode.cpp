#include "vscode/vscode.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <unordered_map>

#include "crypto/sha256.h"

namespace abyss::vscode {

namespace fs = std::filesystem;

namespace {

std::string lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return r;
}

Finding makeFinding(const std::string& ruleId, const std::string& name, Severity sev, Confidence conf,
                     const std::string& desc, const std::string& relPath, const std::string& evidence,
                     std::vector<std::string> tags) {
    Finding f;
    f.findingId = nextFindingId();
    f.ruleId = ruleId;
    f.ruleName = name;
    f.type = RuleType::Behavior;
    f.severity = sev;
    f.confidence = conf;
    f.description = desc;
    f.filePath = relPath;
    f.evidence = evidence.size() > 160 ? evidence.substr(0, 160) + "..." : evidence;
    f.tags = std::move(tags);
    return f;
}

std::vector<std::string> collectStrings(const JsonValue* arr) {
    std::vector<std::string> out;
    if (!arr || !arr->isArray()) return out;
    for (const auto& v : arr->asArray()) {
        if (v.isString()) out.push_back(v.asString());
    }
    return out;
}

bool containsAnyOf(const std::string& haystackLower, std::initializer_list<const char*> needles) {
    for (const char* n : needles) {
        if (haystackLower.find(n) != std::string::npos) return true;
    }
    return false;
}

// Token-exact interpreter detection, NOT a substring search — a raw
// `haystack.find("node")` would false-positive on a command that merely
// references a `node_modules` path (e.g. `./node_modules/.bin/eslint`)
// without ever invoking `node` as the interpreter. Each whitespace-
// separated token is reduced to its final path component (handling
// `/usr/bin/node`, `C:\...\node.exe`, `./node`) and checked for an exact
// match against known interpreter/tool executable names.
bool hasInterpreterToken(const std::string& textLower) {
    static const std::set<std::string> interpreters = {
        "node", "node.exe", "nodejs", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
        "cmd", "cmd.exe", "wscript", "wscript.exe", "cscript", "cscript.exe", "bash", "bash.exe",
        "sh", "python", "python.exe", "python3", "python3.exe", "curl", "curl.exe", "wget",
        "wget.exe", "invoke-webrequest", "iwr", "irm",
    };
    std::istringstream iss(textLower);
    std::string tok;
    while (iss >> tok) {
        std::string base = tok;
        auto slash = base.find_last_of("/\\");
        if (slash != std::string::npos) base = base.substr(slash + 1);
        if (interpreters.count(base)) return true;
    }
    return false;
}

// One task's directly-declared execution surface: command/args/script plus
// options.shell and platform (windows/linux/osx) overrides — everything
// that can make VS Code actually run something, deliberately excluding the
// human-facing `label` (a label is display text, not something VS Code
// executes; "echo font.woff2" as a *label* must not be conflated with
// `node font.woff2` as a *command*).
struct TaskInfo {
    std::string label;
    std::string runOn;
    bool hidden = false;
    std::string executionTextLower;
    std::string executionTextRaw;
    bool hasAnyExecutionContent = false;
    std::vector<std::string> dependsOn; // labels
};

void appendExecutionSurface(const JsonValue& obj, std::string& textLower, std::string& textRaw, bool& hasContent) {
    if (const auto* cmd = obj.find("command"); cmd && cmd->isString()) {
        textRaw += " " + cmd->asString();
        textLower += " " + lower(cmd->asString());
        hasContent = true;
    }
    if (const auto* script = obj.find("script"); script && script->isString()) {
        // npm-type tasks: VS Code resolves this to `npm run <script>` —
        // still an executable command, just declared differently.
        textRaw += " " + script->asString();
        textLower += " " + lower(script->asString());
        hasContent = true;
    }
    if (const auto* args = obj.find("args")) {
        for (const auto& a : collectStrings(args)) {
            textRaw += " " + a;
            textLower += " " + lower(a);
        }
    }
    if (const auto* options = obj.find("options"); options && options->isObject()) {
        if (const auto* shell = options->find("shell"); shell && shell->isObject()) {
            if (const auto* exe = shell->find("executable"); exe && exe->isString()) {
                textRaw += " " + exe->asString();
                textLower += " " + lower(exe->asString());
                hasContent = true;
            }
            if (const auto* sargs = shell->find("args")) {
                for (const auto& a : collectStrings(sargs)) {
                    textRaw += " " + a;
                    textLower += " " + lower(a);
                }
            }
        }
    }
}

TaskInfo parseTaskInfo(const JsonValue& task, std::size_t index) {
    TaskInfo info;
    if (const auto* label = task.find("label"); label && label->isString()) info.label = label->asString();
    else if (const auto* taskName = task.find("taskName"); taskName && taskName->isString())
        info.label = taskName->asString(); // legacy tasks.json field
    else
        info.label = "#" + std::to_string(index);

    if (const auto* runOptions = task.find("runOptions"); runOptions && runOptions->isObject()) {
        if (const auto* r = runOptions->find("runOn")) info.runOn = lower(r->asStringOr(""));
    }

    if (const auto* hide = task.find("hide"); hide && hide->isBool() && hide->asBool()) info.hidden = true;
    if (const auto* presentation = task.find("presentation"); presentation && presentation->isObject()) {
        std::string reveal =
            presentation->find("reveal") ? lower(presentation->find("reveal")->asStringOr("")) : "";
        if (reveal == "silent" || reveal == "never") info.hidden = true;
        if (const auto* close = presentation->find("close"); close && close->isBool() && close->asBool())
            info.hidden = true;
        if (const auto* echo = presentation->find("echo"); echo && echo->isBool() && !echo->asBool())
            info.hidden = true;
    }

    appendExecutionSurface(task, info.executionTextLower, info.executionTextRaw, info.hasAnyExecutionContent);

    // Platform-specific overrides (section 5) can hide the real payload
    // behind whichever OS the victim actually runs — always inspected.
    for (const char* plat : {"windows", "linux", "osx"}) {
        if (const auto* p = task.find(plat); p && p->isObject()) {
            appendExecutionSurface(*p, info.executionTextLower, info.executionTextRaw, info.hasAnyExecutionContent);
        }
    }

    // dependsOn: a string, or an array of strings and/or {task,type} objects.
    if (const auto* dep = task.find("dependsOn")) {
        if (dep->isString()) {
            info.dependsOn.push_back(dep->asString());
        } else if (dep->isArray()) {
            for (const auto& d : dep->asArray()) {
                if (d.isString()) info.dependsOn.push_back(d.asString());
                else if (d.isObject()) {
                    if (const auto* t = d.find("task"); t && t->isString()) info.dependsOn.push_back(t->asString());
                }
            }
        }
    }

    info.executionTextLower = trim(info.executionTextLower);
    info.executionTextRaw = trim(info.executionTextRaw);
    return info;
}

struct EffectiveTask {
    bool hidden = false;
    std::string textLower;
    std::string textRaw;
    bool hasAnyExecutionContent = false;
    bool followedDependsOn = false;
};

// Resolves the effective hidden-ness and execution surface for a task by
// following its dependsOn chain breadth-first. A folderOpen task with no
// command of its own but a dependsOn chain still needs its dependencies'
// commands evaluated — that's where the real execution happens. Cycle- and
// size-bounded so a malformed or adversarial task graph can't hang the scan.
EffectiveTask resolveEffective(const std::unordered_map<std::string, TaskInfo>& byLabel, const TaskInfo& root) {
    EffectiveTask eff;
    std::set<std::string> visited;
    std::vector<std::string> queue = {root.label};
    visited.insert(root.label);
    std::size_t guard = 0;

    while (!queue.empty() && guard++ < 256 && visited.size() <= 128) {
        std::string label = queue.back();
        queue.pop_back();
        auto it = byLabel.find(label);
        if (it == byLabel.end()) continue;
        const TaskInfo& t = it->second;
        eff.hidden = eff.hidden || t.hidden;
        eff.hasAnyExecutionContent = eff.hasAnyExecutionContent || t.hasAnyExecutionContent;
        if (!t.executionTextLower.empty()) eff.textLower += " " + t.executionTextLower;
        if (!t.executionTextRaw.empty()) eff.textRaw += " " + t.executionTextRaw;
        for (const auto& dep : t.dependsOn) {
            eff.followedDependsOn = true;
            if (visited.insert(dep).second) queue.push_back(dep);
        }
    }
    eff.textLower = trim(eff.textLower);
    eff.textRaw = trim(eff.textRaw);
    return eff;
}

std::vector<Finding> evaluateTaskList(const std::string& relPath, const JsonArray& tasksArray) {
    std::vector<Finding> findings;

    std::unordered_map<std::string, TaskInfo> byLabel;
    std::vector<TaskInfo> ordered;
    std::size_t idx = 0;
    for (const auto& task : tasksArray) {
        if (!task.isObject()) { idx++; continue; }
        TaskInfo info = parseTaskInfo(task, idx++);
        byLabel[info.label] = info;
        ordered.push_back(info);
    }

    for (const auto& root : ordered) {
        if (root.runOn != "folderopen") continue;
        EffectiveTask eff = resolveEffective(byLabel, root);

        bool interpreterIndicator = hasInterpreterToken(eff.textLower);
        bool urlIndicator = eff.textLower.find("http://") != std::string::npos ||
                             eff.textLower.find("https://") != std::string::npos;

        // Every folderOpen task with real execution content is a finding —
        // visibility reduces suspicion (lower severity/confidence) but does
        // not remove the execution risk (see README.md,
        // "folderOpen" section). A pure orchestration task with nothing to
        // execute at all (empty resolved text) is not flagged.
        if (eff.hasAnyExecutionContent || !eff.textLower.empty()) {
            Severity sev = Severity::Low;
            Confidence conf = Confidence::Low;
            if (eff.hidden && (interpreterIndicator || urlIndicator)) {
                sev = Severity::Critical;
                conf = Confidence::High;
            } else if (eff.hidden) {
                sev = Severity::High;
                conf = Confidence::Medium;
            } else if (interpreterIndicator || urlIndicator) {
                sev = Severity::Medium;
                conf = Confidence::Low;
            }

            findings.push_back(makeFinding(
                "core.vscode_folderopen_execution_surface",
                eff.hidden ? "Hidden auto-executing folderOpen task" : "Visible folderOpen automatic-execution surface",
                sev, conf,
                "Task '" + root.label + "' runs automatically when the folder is opened (runOn: folderOpen)" +
                    std::string(eff.hidden ? ", with its output hidden/suppressed" : ", with its output visible") +
                    (eff.followedDependsOn ? " (resolved through its dependsOn chain)" : "") + ".",
                relPath, eff.textRaw, {"vscode", "folderopen", "auto-execution"}));
        }

        if (interpreterIndicator &&
            containsAnyOf(eff.textLower, {".woff2", ".woff", ".ttf", ".otf", ".png", ".ico", ".dict"})) {
            findings.push_back(makeFinding(
                "core.vscode_task_asset_as_executable", "Task executes a non-script asset file", Severity::Critical,
                Confidence::High,
                "Task '" + root.label + "' passes a font/image-extensioned file to an interpreter/shell. "
                "Extensions are not a security boundary — this matches the fake-font execution pattern. "
                "(A benign task that merely mentions an asset filename without an interpreter — e.g. an "
                "`echo` label or command — does not trigger this.)",
                relPath, eff.textRaw, {"vscode", "fake-asset", "structural"}));
        }

        if (interpreterIndicator && urlIndicator) {
            findings.push_back(makeFinding(
                "core.vscode_task_download_and_execute", "Task downloads and executes remote content",
                Severity::High, Confidence::Medium,
                "Task '" + root.label + "' combines a network reference with a shell/interpreter invocation.",
                relPath, eff.textRaw, {"vscode", "download-exec"}));
        }
    }

    return findings;
}

} // namespace

std::vector<Finding> scanTasksJson(const std::string& relPath, const std::string& content) {
    auto parsed = parseJson(content);
    if (!parsed.ok || !parsed.value.isObject()) return {};
    const JsonValue* tasksVal = parsed.value.find("tasks");
    if (!tasksVal || !tasksVal->isArray()) return {};
    return evaluateTaskList(relPath, tasksVal->asArray());
}

std::vector<Finding> scanCodeWorkspace(const std::string& relPath, const std::string& content) {
    auto parsed = parseJson(content);
    if (!parsed.ok || !parsed.value.isObject()) return {};
    // *.code-workspace embeds the tasks.json schema under a "tasks" object,
    // itself containing a "tasks" array — same shape VS Code's multi-root
    // workspace file format uses.
    const JsonValue* tasksObj = parsed.value.find("tasks");
    if (!tasksObj || !tasksObj->isObject()) return {};
    const JsonValue* tasksArr = tasksObj->find("tasks");
    if (!tasksArr || !tasksArr->isArray()) return {};
    return evaluateTaskList(relPath, tasksArr->asArray());
}

std::string defaultExtensionsRoot() {
    std::string home = getEnvVar("USERPROFILE");
    if (home.empty()) return {};
    fs::path p = fs::path(home) / ".vscode" / "extensions";
    return pathToUtf8(p);
}

std::vector<ExtensionRecord> discoverExtensions(const std::string& extensionsRoot) {
    std::vector<ExtensionRecord> records;
    std::error_code ec;
    if (extensionsRoot.empty() || !fs::exists(extensionsRoot, ec)) return records;

    // A range-based for over directory_iterator always uses the throwing
    // operator++() internally (there is no syntax to hand it an
    // error_code), and skip_permission_denied only covers access-denied
    // errors specifically -- a long path, a transiently-locked file, or a
    // dangling reparse point encountered mid-walk would throw
    // filesystem_error uncaught. Explicit it.increment(ec) below is the
    // non-throwing form used everywhere else in this project for exactly
    // this reason.
    for (fs::directory_iterator it(extensionsRoot, fs::directory_options::skip_permission_denied, ec), end;
         it != end && !ec; it.increment(ec)) {
        const auto& entry = *it;
        std::error_code isDirEc;
        if (!entry.is_directory(isDirEc) || isDirEc) continue;
        fs::path manifestPath = entry.path() / "package.json";
        std::error_code fec;
        if (!fs::exists(manifestPath, fec)) continue;

        std::vector<std::uint8_t> bytes;
        bool truncated = false;
        if (!readFileBytes(pathToUtf8(manifestPath), bytes, truncated, 8ull * 1024 * 1024)) continue;

        // A malformed manifest is skipped, never a crash — extensions are
        // third-party-authored data we don't control the shape of.
        auto parsed = parseJson(bytesToStringLossy(bytes));
        if (!parsed.ok || !parsed.value.isObject()) continue;

        ExtensionRecord rec;
        rec.path = pathToUtf8(entry.path());
        rec.name = parsed.value.find("name") ? parsed.value.find("name")->asStringOr("") : "";
        rec.publisher = parsed.value.find("publisher") ? parsed.value.find("publisher")->asStringOr("") : "";
        rec.version = parsed.value.find("version") ? parsed.value.find("version")->asStringOr("") : "";
        rec.id = rec.publisher.empty() ? rec.name : rec.publisher + "." + rec.name;
        rec.main = parsed.value.find("main") ? parsed.value.find("main")->asStringOr("") : "";
        rec.browser = parsed.value.find("browser") ? parsed.value.find("browser")->asStringOr("") : "";
        rec.activationEvents = collectStrings(parsed.value.find("activationEvents"));
        rec.extensionDependencies = collectStrings(parsed.value.find("extensionDependencies"));

        if (const auto* deps = parsed.value.find("dependencies"); deps && deps->isObject()) {
            for (const auto& [depName, depVal] : deps->asObject()) {
                (void)depVal;
                rec.dependencies.push_back(depName);
            }
        }
        if (const auto* contrib = parsed.value.find("contributes"); contrib && contrib->isObject()) {
            for (const auto& [key, val] : contrib->asObject()) {
                (void)val;
                rec.contributesKeys.push_back(key);
            }
        }
        rec.manifestSha256 = crypto::sha256Hex(bytes);

        records.push_back(std::move(rec));
    }
    return records;
}

std::vector<Finding> scanExtensionRecord(const ExtensionRecord& ext) {
    std::vector<Finding> findings;
    std::string pseudoPath = "vscode-extension:" + (ext.id.empty() ? ext.path : ext.id);

    bool broadActivation = std::any_of(ext.activationEvents.begin(), ext.activationEvents.end(),
                                        [](const std::string& e) { return e == "*"; });
    if (broadActivation && ext.contributesKeys.empty()) {
        findings.push_back(makeFinding(
            "core.vscode_extension_broad_activation_no_contribution",
            "Extension activates unconditionally with no declared contribution", Severity::Medium,
            Confidence::Low,
            "Extension '" + (ext.id.empty() ? ext.path : ext.id) +
                "' declares activationEvents:[\"*\"] (runs on every VS Code startup) but contributes no "
                "commands/languages/views/etc. Legitimate extensions activating this broadly almost always "
                "contribute something; this combination alone is weak evidence, not proof.",
            pseudoPath, ext.main.empty() ? ext.browser : ext.main,
            {"vscode", "extension", "activation-surface"}));
    }

    for (const auto& entry : {ext.main, ext.browser}) {
        if (entry.empty()) continue;
        if (entry.find("..") != std::string::npos) {
            findings.push_back(makeFinding(
                "core.vscode_extension_entrypoint_traversal", "Extension entry point escapes its own directory",
                Severity::High, Confidence::Medium,
                "Extension '" + (ext.id.empty() ? ext.path : ext.id) + "' declares an entry point ('" + entry +
                    "') containing '..', which can point execution outside the extension's own installed "
                    "directory.",
                pseudoPath, entry, {"vscode", "extension", "path-traversal"}));
        }
    }

    return findings;
}

} // namespace abyss::vscode
