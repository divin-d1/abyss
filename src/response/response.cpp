#include "response/response.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>

#include "crypto/sha256.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#endif

namespace fs = std::filesystem;

namespace abyss::response {
namespace {

std::string canonicalString(const fs::path& path, std::error_code& ec) {
    fs::path p = fs::weakly_canonical(path, ec);
    if (ec) return {};
    return p.lexically_normal().string();
}

std::string hexEncode(const std::string& value) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(value.size() * 2);
    for (unsigned char c : value) {
        out.push_back(digits[c >> 4]);
        out.push_back(digits[c & 0x0f]);
    }
    return out;
}

bool hexDecode(const std::string& value, std::string& out) {
    if ((value.size() & 1u) != 0) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    out.reserve(value.size() / 2);
    for (std::size_t i = 0; i < value.size(); i += 2) {
        int hi = nibble(value[i]), lo = nibble(value[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return true;
}

std::vector<std::string> split(const std::string& line, char delimiter) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (true) {
        std::size_t pos = line.find(delimiter, start);
        out.push_back(line.substr(start, pos == std::string::npos ? pos : pos - start));
        if (pos == std::string::npos) break;
        start = pos + 1;
    }
    return out;
}

std::string fileSha256(const fs::path& path, bool& ok) {
    std::vector<std::uint8_t> bytes;
    bool truncated = false;
    ok = readFileBytes(path.string(), bytes, truncated, 512ull * 1024 * 1024) && !truncated;
    return ok ? crypto::sha256Hex(bytes) : std::string{};
}

std::string recordId(const std::string& path, const std::string& sha) {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    const std::string seed = std::to_string(millis) + "|" + path + "|" + sha;
    std::vector<std::uint8_t> bytes(seed.begin(), seed.end());
    return std::to_string(millis) + "-" + crypto::sha256Hex(bytes).substr(0, 16);
}

bool appendJournal(const fs::path& journal, const QuarantineRecord& rec,
                   const std::string& operation, std::string& error) {
    std::ofstream out(journal, std::ios::binary | std::ios::app);
    if (!out) {
        error = "cannot open quarantine journal";
        return false;
    }
    out << operation << '|' << rec.id << '|' << rec.sha256 << '|'
        << hexEncode(rec.originalPath) << '|' << hexEncode(rec.storedPath) << '|'
        << hexEncode(rec.ruleId) << '|' << hexEncode(rec.reason) << "\n";
    out.flush();
    if (!out) {
        error = "cannot commit quarantine journal record";
        return false;
    }
    return true;
}

bool isRepositoryDir(const fs::path& path) {
    std::error_code ec;
    return fs::is_directory(path / ".git", ec) || fs::is_regular_file(path / ".git", ec);
}

void addCandidateRoot(std::vector<fs::path>& roots, const fs::path& root) {
    std::error_code ec;
    if (!root.empty() && fs::is_directory(root, ec)) roots.push_back(root);
}

#if defined(_WIN32)
// Developers store projects under arbitrary names ("Big Projects", "Client
// Work", "GitHub Repositories") that the fixed \dev, \src, \projects,
// \workspace convention alone would miss. This inspects only a drive's
// immediate children (cheap) and adds matches as extra candidate roots for
// the bounded, depth-limited discovery walk below — it does not itself
// recurse.
bool looksLikeDeveloperRootName(const fs::path& path) {
    std::string name = path.filename().string();
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    static constexpr const char* indicators[] = {
        "code", "dev", "git", "project", "repo", "source", "src", "workspace", "work"
    };
    for (const char* indicator : indicators) {
        if (name.find(indicator) != std::string::npos) return true;
    }
    return false;
}

bool looksSuspiciousLaunchValue(const std::string& input) {
    std::string s = input;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s.find("temp_auto_push") != std::string::npos ||
           s.find("temp_interactive_push") != std::string::npos ||
           s.find("config.bat") != std::string::npos ||
           s.find(".woff2") != std::string::npos ||
           s.find("powershell -enc") != std::string::npos ||
           s.find("powershell.exe -enc") != std::string::npos ||
           s.find("node -e") != std::string::npos;
}

Finding persistenceFinding(const std::string& location, const std::string& evidence) {
    Finding f;
    f.findingId = nextFindingId();
    f.ruleId = "host.persistence.suspicious_launch_value";
    f.ruleName = "Suspicious developer-attack persistence entry";
    f.type = RuleType::Behavior;
    f.severity = Severity::Critical;
    f.confidence = Confidence::High;
    f.description = "A Windows persistence location contains a launch value associated with hidden script or developer-tool execution.";
    f.filePath = location;
    f.evidence = evidence;
    f.tags = {"persistence", "host", "execution"};
    return f;
}

std::string formatIPv4(DWORD addr) {
    const auto* b = reinterpret_cast<const unsigned char*>(&addr);
    return std::to_string(b[0]) + "." + std::to_string(b[1]) + "." + std::to_string(b[2]) + "." +
           std::to_string(b[3]);
}

// dwRemotePort from GetExtendedTcpTable is in network byte order. x86/x64
// Windows is little-endian, so a 16-bit byte swap is the whole conversion —
// this avoids linking ws2_32 for ntohs() over one arithmetic op.
std::uint16_t swapPortBytes(DWORD networkOrderPort) {
    std::uint16_t p = static_cast<std::uint16_t>(networkOrderPort);
    return static_cast<std::uint16_t>((p >> 8) | (p << 8));
}

// Review-only: a script-interpreter process with an established outbound
// connection is common and often entirely legitimate (npm install, VS Code
// extension telemetry, a dev server). Abyss never terminates the process or
// the connection from this data — it only surfaces the correlation for a
// developer investigating a specific incident.
Finding networkFinding(const std::string& location, const std::string& evidence) {
    Finding f;
    f.findingId = nextFindingId();
    f.ruleId = "host.network.interpreter_outbound_connection";
    f.ruleName = "Script interpreter with established outbound connection";
    f.type = RuleType::Behavior;
    f.severity = Severity::Medium;
    f.confidence = Confidence::Low;
    f.description = "A script-interpreter process (node/wscript/cscript/powershell/mshta) holds an "
                    "established outbound TCP connection. This is common in legitimate development "
                    "workflows and is reported for review only, never acted on automatically.";
    f.filePath = location;
    f.evidence = evidence;
    f.tags = {"network", "host", "review-only"};
    return f;
}
#endif

} // namespace

std::string defaultStateRoot() {
#if defined(_WIN32)
    std::string programData = getEnvVar("ProgramData");
    if (!programData.empty()) return (fs::path(programData) / "Abyss").string();
#endif
    return (fs::temp_directory_path() / "Abyss-development-state").string();
}

HostDiscovery discoverHostTargets(std::size_t maxDepth, std::size_t maxDirectories) {
    HostDiscovery result;
    std::vector<fs::path> roots;

#if defined(_WIN32)
    const std::string systemDrive = getEnvVar("SystemDrive");
    if (!systemDrive.empty()) addCandidateRoot(roots, fs::path(systemDrive + "\\Users"));
    const std::string profile = getEnvVar("USERPROFILE");
    addCandidateRoot(roots, profile);
    for (char letter = 'C'; letter <= 'Z'; ++letter) {
        std::string drive;
        drive += letter;
        drive += ":\\";
        UINT type = GetDriveTypeA(drive.c_str());
        if (type == DRIVE_FIXED) {
            addCandidateRoot(roots, fs::path(drive) / "dev");
            addCandidateRoot(roots, fs::path(drive) / "src");
            addCandidateRoot(roots, fs::path(drive) / "projects");
            addCandidateRoot(roots, fs::path(drive) / "workspace");

            std::error_code driveEc;
            for (fs::directory_iterator it(drive, fs::directory_options::skip_permission_denied, driveEc), end;
                 it != end; it.increment(driveEc)) {
                if (driveEc) { driveEc.clear(); continue; }
                std::error_code typeEc;
                if (!it->is_directory(typeEc) || it->is_symlink(typeEc) || isReparsePoint(it->path())) continue;
                if (looksLikeDeveloperRootName(it->path())) addCandidateRoot(roots, it->path());
            }
        }
    }
#else
    addCandidateRoot(roots, getEnvVar("HOME"));
    addCandidateRoot(roots, fs::current_path());
#endif

    std::set<std::string> seenRoots;
    std::set<std::string> seenTargets;
    std::vector<fs::path> directTargets;
#if defined(_WIN32)
    if (!systemDrive.empty()) {
        fs::path users = fs::path(systemDrive + "\\Users");
        std::error_code usersEc;
        for (fs::directory_iterator it(users, fs::directory_options::skip_permission_denied, usersEc), end;
             it != end; it.increment(usersEc)) {
            if (usersEc) { usersEc.clear(); continue; }
            if (!it->is_directory(usersEc)) continue;
            directTargets.push_back(it->path() / ".vscode/extensions");
            directTargets.push_back(it->path() / "AppData/Roaming/npm");
            directTargets.push_back(it->path() / "AppData/Local/npm-cache");
            directTargets.push_back(it->path() / "AppData/Local/Temp");
        }
    }
#else
    const std::string home = getEnvVar("HOME");
    if (!home.empty()) {
        directTargets.push_back(fs::path(home) / ".vscode/extensions");
        directTargets.push_back(fs::path(home) / ".npm");
    }
#endif
    for (const auto& target : directTargets) {
        std::error_code targetEc;
        if (!fs::is_directory(target, targetEc)) continue;
        std::string key = canonicalString(target, targetEc);
        if (!key.empty() && seenTargets.insert(key).second)
            result.targets.push_back({key, "developer-root"});
    }
    for (const auto& rawRoot : roots) {
        std::error_code ec;
        std::string rootKey = canonicalString(rawRoot, ec);
        if (rootKey.empty() || !seenRoots.insert(rootKey).second) continue;

        struct Pending { fs::path path; std::size_t depth; };
        std::vector<Pending> pending{{rawRoot, 0}};
        while (!pending.empty() && result.directoriesVisited < maxDirectories) {
            Pending current = std::move(pending.back());
            pending.pop_back();
            ++result.directoriesVisited;

            if (isRepositoryDir(current.path)) {
                std::string key = canonicalString(current.path, ec);
                if (!key.empty() && seenTargets.insert(key).second)
                    result.targets.push_back({key, "repository"});
                continue; // each repository is scanned independently; do not find nested vendor repos
            }
            if (current.depth >= maxDepth) continue;

            fs::directory_iterator it(current.path, fs::directory_options::skip_permission_denied, ec), end;
            if (ec) {
                result.errors.push_back(current.path.string() + ": " + ec.message());
                ec.clear();
                continue;
            }
            for (; it != end; it.increment(ec)) {
                if (ec) { result.errors.push_back(current.path.string() + ": " + ec.message()); ec.clear(); continue; }
                const fs::path p = it->path();
                const std::string name = p.filename().string();
                if (name == ".git" || name == "node_modules" || name == ".cache" ||
                    name == "AppData" || name == "$Recycle.Bin" || name == "System Volume Information") continue;
                std::error_code typeEc;
                if (it->is_symlink(typeEc) || isReparsePoint(p)) continue;
                if (it->is_directory(typeEc)) pending.push_back({p, current.depth + 1});
            }
        }
    }
    if (result.directoriesVisited >= maxDirectories)
        result.errors.push_back("host discovery reached its directory safety limit");
    return result;
}

std::vector<Finding> inspectPersistence() {
    std::vector<Finding> findings;
#if defined(_WIN32)
    struct KeySpec { HKEY root; const char* path; const char* label; };
    const KeySpec keys[] = {
        {HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU Run"},
        {HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU RunOnce"},
        {HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM Run"},
        {HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM RunOnce"},
    };
    for (const auto& spec : keys) {
        HKEY key = nullptr;
        if (RegOpenKeyExA(spec.root, spec.path, 0, KEY_READ, &key) != ERROR_SUCCESS) continue;
        for (DWORD index = 0;; ++index) {
            char name[512]{}; BYTE data[8192]{};
            DWORD nameSize = static_cast<DWORD>(sizeof(name));
            DWORD dataSize = static_cast<DWORD>(sizeof(data));
            DWORD type = 0;
            LONG status = RegEnumValueA(key, index, name, &nameSize, nullptr, &type, data, &dataSize);
            if (status == ERROR_NO_MORE_ITEMS) break;
            if (status != ERROR_SUCCESS) continue;
            if ((type == REG_SZ || type == REG_EXPAND_SZ) && dataSize > 0) {
                std::size_t length = 0;
                while (length < dataSize && data[length] != 0) ++length;
                std::string value(reinterpret_cast<char*>(data), length);
                if (looksSuspiciousLaunchValue(value))
                    findings.push_back(persistenceFinding(std::string(spec.label) + "/" + name, value));
            }
        }
        RegCloseKey(key);
    }

    std::vector<fs::path> startupRoots;
    std::string appData = getEnvVar("APPDATA");
    std::string programData = getEnvVar("ProgramData");
    if (!appData.empty()) startupRoots.push_back(fs::path(appData) / "Microsoft/Windows/Start Menu/Programs/Startup");
    if (!programData.empty()) startupRoots.push_back(fs::path(programData) / "Microsoft/Windows/Start Menu/Programs/Startup");
    for (const auto& root : startupRoots) {
        std::error_code ec;
        for (fs::directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end; it != end; it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            std::vector<std::uint8_t> bytes; bool truncated = false;
            if (readFileBytes(it->path().string(), bytes, truncated, 2 * 1024 * 1024) && !truncated) {
                std::string text = bytesToStringLossy(bytes);
                if (looksSuspiciousLaunchValue(text) || looksSuspiciousLaunchValue(it->path().filename().string()))
                    findings.push_back(persistenceFinding(it->path().string(), text.substr(0, 240)));
            }
        }
    }

    // Scheduled task definitions are XML files on disk. Reading them
    // directly avoids executing task scheduler actions or invoking a shell.
    std::string windowsDir = getEnvVar("SystemRoot");
    if (!windowsDir.empty()) {
        fs::path tasks = fs::path(windowsDir) / "System32" / "Tasks";
        std::error_code ec;
        for (fs::recursive_directory_iterator it(tasks, fs::directory_options::skip_permission_denied, ec), end;
             it != end; it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (!it->is_regular_file(ec)) continue;
            std::vector<std::uint8_t> bytes; bool truncated = false;
            if (readFileBytes(it->path().string(), bytes, truncated, 2 * 1024 * 1024) && !truncated) {
                std::string text = bytesToStringLossy(bytes);
                if (looksSuspiciousLaunchValue(text))
                    findings.push_back(persistenceFinding("Scheduled task: " + it->path().string(), text.substr(0, 240)));
            }
        }
    }

    // PowerShell profiles are common user-level persistence points.
    const std::string userProfile = getEnvVar("USERPROFILE");
    if (!userProfile.empty()) {
        const fs::path profiles[] = {
            fs::path(userProfile) / "Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
            fs::path(userProfile) / "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
            fs::path(userProfile) / "Documents/WindowsPowerShell/profile.ps1",
            fs::path(userProfile) / "Documents/PowerShell/profile.ps1"
        };
        for (const auto& profile : profiles) {
            std::vector<std::uint8_t> bytes; bool truncated = false;
            if (readFileBytes(profile.string(), bytes, truncated, 2 * 1024 * 1024) && !truncated) {
                std::string text = bytesToStringLossy(bytes);
                if (looksSuspiciousLaunchValue(text))
                    findings.push_back(persistenceFinding("PowerShell profile: " + profile.string(), text.substr(0, 240)));
            }
        }
    }

    // Service binary paths are configuration data. No service is started,
    // stopped, or queried through its own executable.
    SC_HANDLE manager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (manager) {
        DWORD bytesNeeded = 0, count = 0, resume = 0;
        EnumServicesStatusExA(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                              SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded, &count, &resume, nullptr);
        if (GetLastError() == ERROR_MORE_DATA && bytesNeeded > 0 && bytesNeeded < 64 * 1024 * 1024) {
            std::vector<BYTE> buffer(bytesNeeded);
            resume = 0;
            if (EnumServicesStatusExA(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                      SERVICE_STATE_ALL, buffer.data(), bytesNeeded,
                                      &bytesNeeded, &count, &resume, nullptr)) {
                auto entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSA*>(buffer.data());
                for (DWORD i = 0; i < count; ++i) {
                    SC_HANDLE service = OpenServiceA(manager, entries[i].lpServiceName, SERVICE_QUERY_CONFIG);
                    if (!service) continue;
                    DWORD configBytes = 0;
                    QueryServiceConfigA(service, nullptr, 0, &configBytes);
                    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && configBytes > 0 && configBytes < 1024 * 1024) {
                        std::vector<BYTE> configBuffer(configBytes);
                        auto config = reinterpret_cast<QUERY_SERVICE_CONFIGA*>(configBuffer.data());
                        if (QueryServiceConfigA(service, config, configBytes, &configBytes) &&
                            config->lpBinaryPathName && looksSuspiciousLaunchValue(config->lpBinaryPathName)) {
                            findings.push_back(persistenceFinding(std::string("Service: ") + entries[i].lpServiceName,
                                                                 config->lpBinaryPathName));
                        }
                    }
                    CloseServiceHandle(service);
                }
            }
        }
        CloseServiceHandle(manager);
    }

    // Process enumeration is read-only. A suspicious process is surfaced for
    // response review; Abyss never terminates a process on a weak name match.
    std::unordered_map<DWORD, std::string> processNames;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        // Toolhelp32 predates the A/W suffix convention: there is no
        // PROCESSENTRY32A/Process32FirstA/Process32NextA in the Windows SDK,
        // only the unsuffixed (ANSI, since UNICODE is not defined in this
        // project) names used here, and the explicit ...W wide variants.
        PROCESSENTRY32 entry{}; entry.dwSize = sizeof(entry);
        if (Process32First(snapshot, &entry)) {
            do {
                processNames[entry.th32ProcessID] = entry.szExeFile;
                if (looksSuspiciousLaunchValue(entry.szExeFile))
                    findings.push_back(persistenceFinding(std::string("Process PID ") + std::to_string(entry.th32ProcessID),
                                                         entry.szExeFile));
            } while (Process32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    // Network connections are read-only correlation: established outbound
    // TCP connections owned by a script-interpreter process. Abyss never
    // closes a socket or kills a process based on this data.
    static const std::vector<std::string> interpreterNames = {
        "node.exe", "wscript.exe", "cscript.exe", "powershell.exe", "pwsh.exe", "mshta.exe",
    };
    DWORD tcpTableSize = 0;
    GetExtendedTcpTable(nullptr, &tcpTableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcpTableSize > 0 && tcpTableSize < 16 * 1024 * 1024) {
        std::vector<BYTE> tcpBuffer(tcpTableSize);
        if (GetExtendedTcpTable(tcpBuffer.data(), &tcpTableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) ==
            NO_ERROR) {
            auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(tcpBuffer.data());
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                const auto& row = table->table[i];
                if (row.dwState != MIB_TCP_STATE_ESTAB) continue;
                auto it = processNames.find(row.dwOwningPid);
                if (it == processNames.end()) continue;
                std::string lowerName = it->second;
                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
                              [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                bool isInterpreter = std::find(interpreterNames.begin(), interpreterNames.end(), lowerName) !=
                                    interpreterNames.end();
                bool isLoopback = reinterpret_cast<const unsigned char*>(&row.dwRemoteAddr)[0] == 127;
                if (isInterpreter && !isLoopback) {
                    findings.push_back(networkFinding(
                        "Process PID " + std::to_string(row.dwOwningPid) + " (" + it->second + ")",
                        "established connection to " + formatIPv4(row.dwRemoteAddr) + ":" +
                            std::to_string(swapPortBytes(row.dwRemotePort))));
                }
            }
        }
    }
#endif
    return findings;
}

RemediationPlan buildPlan(const std::string& scanRoot, const std::vector<Finding>& findings) {
    RemediationPlan plan;
    std::error_code ec;
    fs::path root = fs::weakly_canonical(scanRoot, ec);
    plan.scanRoot = ec ? scanRoot : root.string();
    std::set<std::string> plannedFiles;
    for (const auto& finding : findings) {
        RemediationAction action;
        action.findingId = finding.findingId;
        action.ruleId = finding.ruleId;
        action.reason = finding.description;
        if (finding.filePath.empty() || finding.filePath.rfind("vscode-extension:", 0) == 0) {
            action.refusal = "finding does not identify a repository file";
        } else if (finding.severity != Severity::Critical || finding.confidence != Confidence::Confirmed) {
            action.refusal = "automatic quarantine requires Critical/Confirmed evidence";
        } else {
            fs::path source = root / fs::path(finding.filePath);
            fs::path canonical = fs::weakly_canonical(source, ec);
            if (ec || !pathStartsWith(canonical, root)) action.refusal = "path escapes or cannot be resolved inside scan root";
            else if (isReparsePoint(canonical) || fs::is_symlink(canonical, ec)) action.refusal = "links and reparse points are never quarantined automatically";
            else if (!fs::is_regular_file(canonical, ec)) action.refusal = "target is not a regular file";
            else if (!plannedFiles.insert(canonical.string()).second)
                action.refusal = "the same file is already covered by an earlier confirmed action";
            else { action.eligible = true; action.sourcePath = canonical.string(); }
        }
        plan.actions.push_back(std::move(action));
        ec.clear();
    }
    return plan;
}

RemediationResult applyPlan(const RemediationPlan& plan, const std::string& stateRoot, bool confirmed) {
    RemediationResult result;
    if (!confirmed) {
        result.errors.push_back("remediation was not confirmed; no files were changed");
        return result;
    }
    fs::path root = fs::path(stateRoot);
    fs::path store = root / "quarantine" / "objects";
    fs::path journal = root / "quarantine" / "journal.v1";
    std::error_code ec;
    fs::create_directories(store, ec);
    if (ec) { result.errors.push_back("cannot create quarantine: " + ec.message()); return result; }

    for (const auto& action : plan.actions) {
        if (!action.eligible) {
            result.skipped.push_back(action.findingId + ": " + action.refusal);
            continue;
        }
        bool hashOk = false;
        const std::string originalHash = fileSha256(action.sourcePath, hashOk);
        if (!hashOk || originalHash.empty()) {
            result.errors.push_back(action.sourcePath + ": cannot hash complete source file");
            continue;
        }
        QuarantineRecord rec;
        rec.id = recordId(action.sourcePath, originalHash);
        rec.originalPath = action.sourcePath;
        rec.sha256 = originalHash;
        rec.ruleId = action.ruleId;
        rec.reason = action.reason;
        fs::path stored = store / (rec.id + ".quarantine");
        rec.storedPath = stored.string();

        fs::copy_file(action.sourcePath, stored, fs::copy_options::none, ec);
        if (ec) { result.errors.push_back(action.sourcePath + ": quarantine copy failed: " + ec.message()); ec.clear(); continue; }
        bool storedHashOk = false;
        const std::string storedHash = fileSha256(stored, storedHashOk);
        if (!storedHashOk || storedHash != originalHash) {
            result.errors.push_back(action.sourcePath + ": quarantine verification failed; original was left unchanged");
            continue;
        }
        std::string journalError;
        if (!appendJournal(journal, rec, "QUARANTINE", journalError)) {
            result.errors.push_back(action.sourcePath + ": " + journalError + "; original was left unchanged");
            continue;
        }
        fs::remove(action.sourcePath, ec);
        if (ec) {
            result.errors.push_back(action.sourcePath + ": protected copy created but active file could not be removed: " + ec.message());
            ec.clear();
            continue;
        }
        result.quarantined.push_back(std::move(rec));
    }
    return result;
}

std::vector<QuarantineRecord> listQuarantine(const std::string& stateRoot, std::vector<std::string>* errors) {
    std::vector<QuarantineRecord> records;
    std::map<std::string, std::size_t> byId;
    std::ifstream in(fs::path(stateRoot) / "quarantine" / "journal.v1", std::ios::binary);
    if (!in) return records;
    std::string line;
    while (std::getline(in, line)) {
        auto fields = split(line, '|');
        if (fields.size() != 7 || (fields[0] != "QUARANTINE" && fields[0] != "RESTORE")) {
            if (errors) errors->push_back("malformed quarantine journal record");
            continue;
        }
        if (fields[0] == "RESTORE") {
            auto it = byId.find(fields[1]);
            if (it != byId.end()) records[it->second].restored = true;
            continue;
        }
        QuarantineRecord rec;
        rec.id = fields[1]; rec.sha256 = fields[2];
        if (!hexDecode(fields[3], rec.originalPath) || !hexDecode(fields[4], rec.storedPath) ||
            !hexDecode(fields[5], rec.ruleId) || !hexDecode(fields[6], rec.reason)) {
            if (errors) errors->push_back("invalid encoding in quarantine journal record");
            continue;
        }
        byId[rec.id] = records.size();
        records.push_back(std::move(rec));
    }
    return records;
}

bool restoreQuarantine(const std::string& stateRoot, const std::string& id, bool overwrite, std::string& error) {
    auto records = listQuarantine(stateRoot, nullptr);
    auto it = std::find_if(records.begin(), records.end(), [&](const auto& r) { return r.id == id; });
    if (it == records.end()) { error = "quarantine record not found"; return false; }
    if (it->restored) { error = "quarantine record was already restored"; return false; }
    bool hashOk = false;
    if (fileSha256(it->storedPath, hashOk) != it->sha256 || !hashOk) {
        error = "quarantined object failed integrity verification";
        return false;
    }
    std::error_code ec;
    if (fs::exists(it->originalPath, ec) && !overwrite) {
        error = "original path already exists; use --force only after reviewing it";
        return false;
    }
    fs::create_directories(fs::path(it->originalPath).parent_path(), ec);
    if (ec) { error = "cannot recreate original directory: " + ec.message(); return false; }
    fs::copy_file(it->storedPath, it->originalPath,
                  overwrite ? fs::copy_options::overwrite_existing : fs::copy_options::none, ec);
    if (ec) { error = "restore copy failed: " + ec.message(); return false; }
    std::string journalError;
    QuarantineRecord rec = *it;
    if (!appendJournal(fs::path(stateRoot) / "quarantine" / "journal.v1", rec, "RESTORE", journalError)) {
        error = journalError;
        return false;
    }
    return true;
}

std::vector<std::string> protectedRoots(const std::string& stateRoot, std::vector<std::string>* errors) {
    std::vector<std::string> roots;
    std::ifstream in(fs::path(stateRoot) / "protected-roots.v1", std::ios::binary);
    if (!in) return roots;
    std::string line, decoded;
    while (std::getline(in, line)) {
        if (!hexDecode(line, decoded)) { if (errors) errors->push_back("malformed protected-root record"); continue; }
        roots.push_back(decoded);
    }
    return roots;
}

bool writeProtectedRoots(const std::string& stateRoot, const std::vector<std::string>& roots, std::string& error) {
    std::error_code ec;
    fs::create_directories(stateRoot, ec);
    if (ec) { error = "cannot create protection state directory: " + ec.message(); return false; }
    fs::path target = fs::path(stateRoot) / "protected-roots.v1";
    fs::path temp = fs::path(stateRoot) / "protected-roots.v1.new";
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    if (!out) { error = "cannot write protection state"; return false; }
    for (const auto& root : roots) out << hexEncode(root) << "\n";
    out.flush();
    if (!out) { error = "cannot commit protection state"; return false; }
    out.close();
    fs::rename(temp, target, ec);
    if (ec) {
        fs::remove(target, ec); ec.clear();
        fs::rename(temp, target, ec);
    }
    if (ec) { error = "cannot replace protection state: " + ec.message(); return false; }
    return true;
}

bool addProtectedRoot(const std::string& stateRoot, const std::string& root, std::string& error) {
    std::error_code ec;
    std::string canonical = canonicalString(root, ec);
    if (canonical.empty() || !fs::is_directory(canonical, ec)) { error = "protected root is not a readable directory"; return false; }
    auto roots = protectedRoots(stateRoot, nullptr);
    if (std::find(roots.begin(), roots.end(), canonical) == roots.end()) roots.push_back(canonical);
    return writeProtectedRoots(stateRoot, roots, error);
}

bool removeProtectedRoot(const std::string& stateRoot, const std::string& root, std::string& error) {
    std::error_code ec;
    std::string canonical = canonicalString(root, ec);
    auto roots = protectedRoots(stateRoot, nullptr);
    roots.erase(std::remove(roots.begin(), roots.end(), canonical), roots.end());
    return writeProtectedRoots(stateRoot, roots, error);
}

bool installRepositoryGuards(const std::string& repository, const std::string& abyssExecutable,
                             std::vector<std::string>& messages, std::string& error) {
    fs::path repo(repository);
    fs::path git = repo / ".git";
    std::error_code ec;
    if (!fs::is_directory(git, ec)) { error = "repository has no .git directory"; return false; }
    fs::path hooks = git / "hooks";
    fs::create_directories(hooks, ec);
    if (ec) { error = "cannot create hooks directory: " + ec.message(); return false; }

#if defined(_WIN32)
    std::string exeForShell = abyssExecutable;
    std::string repoForShell = repo.string();
    std::replace(exeForShell.begin(), exeForShell.end(), '\\', '/');
    std::replace(repoForShell.begin(), repoForShell.end(), '\\', '/');
    const std::string hookBody = "#!/bin/sh\nexec \"" + exeForShell + "\" preflight \"" + repoForShell + "\"\n";
    const char* names[] = {"pre-commit", "pre-push"};
#else
    const std::string hookBody = "#!/bin/sh\nexec \"" + abyssExecutable + "\" preflight \"" + repo.string() + "\"\n";
    const char* names[] = {"pre-commit", "pre-push"};
#endif
    for (const char* name : names) {
        fs::path hook = hooks / name;
        if (fs::exists(hook, ec)) { messages.push_back(hook.string() + " preserved (existing hook)"); continue; }
        std::ofstream out(hook, std::ios::binary | std::ios::trunc);
        if (!out) { error = "cannot write repository guard: " + hook.string(); return false; }
        out << hookBody;
        out.close();
#if !defined(_WIN32)
        fs::permissions(hook, fs::perms::owner_exec | fs::perms::owner_read | fs::perms::owner_write,
                        fs::perm_options::add, ec);
#endif
        messages.push_back(hook.string() + " installed");
    }
    return true;
}

bool removeRepositoryGuards(const std::string& repository, const std::string& abyssExecutable,
                            std::vector<std::string>& messages, std::string& error) {
    fs::path repo(repository);
    std::string exeForShell = abyssExecutable;
    std::string repoForShell = repo.string();
    std::replace(exeForShell.begin(), exeForShell.end(), '\\', '/');
    std::replace(repoForShell.begin(), repoForShell.end(), '\\', '/');
    const std::string ownedBody = "#!/bin/sh\nexec \"" + exeForShell + "\" preflight \"" + repoForShell + "\"\n";
    for (const char* name : {"pre-commit", "pre-push"}) {
        fs::path hook = repo / ".git" / "hooks" / name;
        std::string body;
        {
            // The read handle must be closed before fs::remove: Windows
            // does not allow deleting a file through a handle that is still
            // open without FILE_SHARE_DELETE, which std::ifstream does not
            // request. Scoping `in` ensures its destructor (which closes
            // the handle) runs before the removal attempt below.
            std::ifstream in(hook, std::ios::binary);
            if (!in) continue;
            body.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        }
        if (body != ownedBody) {
            messages.push_back(hook.string() + " preserved (not owned by Abyss)");
            continue;
        }
        std::error_code ec;
        if (!fs::remove(hook, ec) || ec) {
            error = "cannot remove repository guard: " + hook.string();
            return false;
        }
        messages.push_back(hook.string() + " removed");
    }
    return true;
}

} // namespace abyss::response
