#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <vector>
#include <thread>

#if !defined(_WIN32)
#include <unistd.h>
#endif

#include "core/core.h"
#include "crypto/sha256.h"
#include "evidence/evidence.h"
#include "git/safe_git.h"
#include "preflight/esr.h"
#include "response/response.h"
#include "rules/rules.h"
#include "scanner/scanner.h"
#include "vscode/vscode.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace fs = std::filesystem;
using namespace abyss;

namespace {

constexpr const char* kAbyssVersion = "1.0.0";

std::string exeDirectory() {
#if defined(_WIN32)
    char buf[MAX_PATH];
    DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (n == 0 || n == MAX_PATH) return fs::current_path().string();
    return fs::path(buf).parent_path().string();
#else
    std::error_code ec;
    fs::path executable = fs::read_symlink("/proc/self/exe", ec);
    return ec ? fs::current_path().string() : executable.parent_path().string();
#endif
}

std::string programDataRulesDir() {
    std::string pd = getEnvVar("ProgramData");
    if (pd.empty()) return {};
    return (fs::path(pd) / "Abyss" / "rules").string();
}

// Official rule search: exactly two deterministic candidates — the rules/
// directory installed alongside the executable itself, or
// %ProgramData%\Abyss\rules. No parent-directory walking (a previous
// version tried exe/../rules, exe/../../rules, etc., which meant copying
// abyss.exe into an attacker-controlled directory tree could cause it to
// pick up a rules/ folder several levels up that the attacker placed) and
// never the current working directory or anything under the directory
// being scanned. See README.md "Trusted rule boundary".
std::string findOfficialRulesDirectory() {
    fs::path installRelative = fs::path(exeDirectory()) / "rules";
    std::error_code ec;
    if (fs::exists(installRelative, ec)) return fs::weakly_canonical(installRelative, ec).string();

    std::string pd = programDataRulesDir();
    if (!pd.empty() && fs::exists(pd, ec)) return fs::weakly_canonical(pd, ec).string();

    return {};
}

void printUsage() {
    std::cout <<
        "Abyss " << kAbyssVersion << " - developer supply-chain security platform\n\n"
        "  abyss check                    Environment/rule-trust sanity check\n"
        "  abyss scan <path> [--json]     Static scan of a repository or directory\n"
        "  abyss scan-all <parent> [--yes] Scan each project inside a parent directory; --yes also\n"
        "                                  quarantines confirmed evidence in every BLOCKED project\n"
        "  abyss system-scan [--json]     Discover and scan developer repositories on this PC\n"
        "  abyss preflight <path>         Scan + explicit ALLOW/BLOCK decision\n"
        "  abyss open <path>              Preflight gate before opening a project\n"
        "  abyss contain <path> [--yes]   Plan or apply confirmed-evidence quarantine\n"
        "  abyss remediate <path> --yes   Quarantine confirmed evidence and verify again\n"
        "  abyss verify <path>            Independent post-remediation scan\n"
        "  abyss quarantine list          List protected quarantine records\n"
        "  abyss quarantine restore <id> [--force]\n"
        "  abyss clone <url> <path>       Stage, scan, then publish a clone\n"
        "  abyss pull <path>              Fetch, stage, scan, then fast-forward\n"
        "  abyss protect <path>           Add persistent local protection and Git guards\n"
        "  abyss unprotect <path>         Remove protection for one path\n"
        "  abyss timeline <path>          Print bounded Git forensic timeline data\n"
        "  abyss graph <path>             Print bounded Git history graph\n"
        "  abyss recover <repo> <commit> <destination>\n"
        "  abyss rules list               List loaded rules and execution surfaces\n"
        "  abyss rules verify             Verify the official rule pack against MANIFEST.sha256\n"
        "  abyss self-scan                Scan Abyss's own installation (release-gate check)\n"
        "  abyss status                   Report Abyss's own protection state\n"
        "  abyss version                  Print the Abyss version\n\n"
        "Running abyss.exe with no arguments (e.g. double-clicking it) opens an interactive\n"
        "menu that walks through the same commands without a command line.\n\n"
        "Options:\n"
        "  --json          Emit JSONL findings to stdout instead of the human report\n"
        "  --yes           Confirm an eligible remediation action\n"
        "  --force         Permit restore over an existing path after review\n"
        "  --rules <dir>   Explicit UNTRUSTED local rule directory override (command-line flag\n"
        "                  only, no environment-variable equivalent; bypasses the official\n"
        "                  trust/integrity check and can never produce an official clean result)\n\n"
        "Exit codes: 0 clean, 1 blocked/security violation, 2 operational failure\n"
        "            (degraded/incomplete), 3 suspicious — manual review recommended,\n"
        "            4 unresolved after a requested response action.\n";
}

struct LoadedEngine {
    rules::RuleEngine ruleEngine{std::vector<rules::Rule>{}};
    preflight::ExecutionSurfaceRegistry esr{std::vector<preflight::ExecutionSurface>{}};
    scanner::ScanThresholds thresholds;
    std::string rulesDir;
    std::vector<std::string> loadErrors;
    evidence::RuleTrustStatus trust;
};

std::string joinSemicolon(const std::vector<std::string>& items) {
    std::string out;
    for (std::size_t i = 0; i < items.size(); i++) out += (i ? "; " : "") + items[i];
    return out;
}

LoadedEngine loadEngine(const std::string& explicitOverrideDir) {
    LoadedEngine loaded;

    // Only an explicit --rules <dir> command-line argument can select an
    // untrusted local rule set — there is deliberately no environment-
    // variable equivalent. An env var is ambient, inherited, and easy to
    // set once and forget; a CLI flag is a conscious choice made on every
    // single invocation, which is the bar for "the operator knowingly
    // asked for this."
    if (!explicitOverrideDir.empty()) {
        std::error_code ec;
        loaded.trust.trustLevel = "untrusted-local";
        if (!fs::exists(explicitOverrideDir, ec)) {
            loaded.trust.integrityStatus = "no-rules-found";
            loaded.trust.degraded = true;
            loaded.trust.details = "explicitly supplied rules directory does not exist: " + explicitOverrideDir;
            return loaded;
        }
        loaded.rulesDir = explicitOverrideDir;
        loaded.trust.integrityStatus = "unverified-untrusted-local";
        // NOT degraded — an explicit, informed operator choice is not the
        // threat the trust boundary defends against — but see
        // evidence::computeVerdict(): trustLevel != "official" caps the
        // best-case verdict below Clean regardless of findings, and every
        // finding produced this way is labeled with this trust level (see
        // writeHumanReport's "Rule trust" section), so a --rules run can
        // never issue an "official clearance" (exit 0) or have its
        // findings mistaken for official-pack results.
        loaded.trust.details =
            "rules explicitly overridden via --rules (command-line flag only, no environment-variable "
            "equivalent); not subject to the official trust/integrity check, and results are never "
            "reported as an official clearance";
    } else {
        loaded.trust.trustLevel = "official";
        loaded.rulesDir = findOfficialRulesDirectory();
        if (loaded.rulesDir.empty()) {
            loaded.trust.integrityStatus = "no-rules-found";
            loaded.trust.degraded = true;
            loaded.trust.details =
                "no official rule pack found in any trusted installation location (exe-relative rules/, "
                "%ProgramData%\\Abyss\\rules) — the scanned directory and current working directory are "
                "never searched automatically";
            return loaded;
        }
        auto verification = rules::verifyRuleManifest(loaded.rulesDir);
        if (!verification.manifestFound) {
            // A missing manifest means integrity cannot be established at
            // all — this is now treated as degraded, not merely
            // "unverified", per the fail-closed requirement: an official
            // clean result must never be issuable without a verified pack.
            loaded.trust.integrityStatus = "no-manifest";
            loaded.trust.degraded = true;
            loaded.trust.details =
                "no MANIFEST.sha256 present in the official rules directory — integrity cannot be "
                "established, so an official clean result cannot be issued (see README.md; run "
                "`abyss rules verify` for detail)";
        } else if (!verification.manifestReadable) {
            loaded.trust.integrityStatus = "unreadable-manifest";
            loaded.trust.degraded = true;
            loaded.trust.details = "MANIFEST.sha256 exists but could not be read: " + joinSemicolon(verification.errors);
        } else if (!verification.allVerified) {
            loaded.trust.integrityStatus = verification.anchorAvailable && !verification.anchorVerified
                                                ? "tampered-anchor-mismatch"
                                                : "tampered";
            loaded.trust.degraded = true;
            std::string details = std::to_string(verification.mismatches.size()) + " mismatch(es): " +
                                   joinSemicolon(verification.mismatches) + ". " +
                                   std::to_string(verification.rejectedPaths.size()) + " rejected path(s): " +
                                   joinSemicolon(verification.rejectedPaths) + ". " +
                                   std::to_string(verification.untracked.size()) + " untracked file(s): " +
                                   joinSemicolon(verification.untracked);
            if (!verification.errors.empty()) details += ". errors: " + joinSemicolon(verification.errors);
            loaded.trust.details = details;
        } else if (!verification.anchorAvailable) {
            // A manifest that matches the files on disk proves internal
            // self-consistency, but self-consistency alone is NOT trust:
            // an attacker who can write both the rules and the manifest
            // can trivially keep them matching each other. Without a hash
            // of the manifest baked into the compiled binary at release
            // time (src/rules/trust_anchor.h), there is no independent
            // basis to believe this manifest is the real one — so this is
            // a hard failure (INCOMPLETE), not a soft pass. This state
            // should only be reachable in an from-source dev build before
            // tools/generate_rules_manifest.ps1 has produced a real
            // anchor; a real release build always has one.
            loaded.trust.integrityStatus = "no-trust-anchor";
            loaded.trust.degraded = true;
            loaded.trust.details =
                "the rule pack's files match its own MANIFEST.sha256, but this binary has no compiled-in "
                "trust anchor to verify the manifest itself against (src/rules/trust_anchor.h is empty) — "
                "self-consistency between a manifest and the files it describes is not sufficient trust, "
                "since an attacker with write access to both could keep them matching each other; a real "
                "release build always compiles in a non-empty anchor";
        } else {
            loaded.trust.integrityStatus = "verified";
        }
    }

    std::vector<rules::Rule> allRules;
    for (const auto& sub : {"core", "filetypes", "git", "vscode", "execution-surfaces", "campaigns"}) {
        auto res = rules::loadRulesFromDirectory((fs::path(loaded.rulesDir) / sub).string());
        allRules.insert(allRules.end(), res.rules.begin(), res.rules.end());
        loaded.loadErrors.insert(loaded.loadErrors.end(), res.errors.begin(), res.errors.end());
    }
    loaded.thresholds =
        scanner::loadThresholds((fs::path(loaded.rulesDir) / "core" / "thresholds.rules").string());
    auto esrRes = preflight::loadExecutionSurfaces((fs::path(loaded.rulesDir) / "execution-surfaces").string());
    loaded.esr = preflight::ExecutionSurfaceRegistry(esrRes.surfaces);
    loaded.loadErrors.insert(loaded.loadErrors.end(), esrRes.errors.begin(), esrRes.errors.end());

    auto dupErrors = rules::findDuplicateRuleIds(allRules);
    loaded.loadErrors.insert(loaded.loadErrors.end(), dupErrors.begin(), dupErrors.end());

    // A corrupt/invalid/ambiguous (duplicate-ID) rule file in the OFFICIAL
    // pack undermines confidence in the completeness of detection — fail
    // closed rather than silently scanning with a partial or ambiguous
    // rule set. A local override's parse errors do not force further
    // degradation (it can never issue official clearance anyway — see
    // above), but are still surfaced.
    if (!loaded.loadErrors.empty() && loaded.trust.trustLevel == "official" && !loaded.trust.degraded) {
        loaded.trust.degraded = true;
        loaded.trust.integrityStatus = "parse-errors";
        loaded.trust.details = std::to_string(loaded.loadErrors.size()) +
                                " rule/ESR parse/validation error(s) in the official pack: " +
                                joinSemicolon(loaded.loadErrors);
    }

    loaded.ruleEngine = rules::RuleEngine(std::move(allRules));
    return loaded;
}

struct ScanRun {
    scanner::ScanReport report;
    evidence::RuleTrustStatus trust;
    evidence::Verdict verdict;
    std::vector<std::string> loadErrors;
    std::string rulesDir;
};

// ---------------------------------------------------------------------------
// Report output. A scan with hundreds of findings scrolling past the
// console at terminal speed reads as alarming and uncontrolled to a
// developer who isn't expecting it — easily mistaken for something actively
// happening to their machine, rather than a static report. The full,
// detailed report (every finding, every evidence excerpt) is written to
// <resultsBaseDir>/abyss-results/results.txt instead; the console gets a
// short, calm summary and the file path. Nothing is ever silently lost: if
// the file can't be written (read-only location, permission denied), the
// full report falls back to printing on the console exactly as before.
// ---------------------------------------------------------------------------

// Returns the written file's path, or empty if it could not be written.
std::string writeReportFile(const std::string& resultsBaseDir, const std::string& scope,
                            const std::vector<Finding>& findings, const scanner::ScanCoverage& coverage,
                            const evidence::RuleTrustStatus& trust, const evidence::Verdict& verdict) {
    std::error_code ec;
    fs::path resultsDir = fs::path(resultsBaseDir) / "abyss-results";
    fs::create_directories(resultsDir, ec);
    if (ec) return {};
    fs::path resultsFile = resultsDir / "results.txt";
    std::ofstream out(resultsFile, std::ios::binary | std::ios::trunc);
    if (!out) return {};
    evidence::writeHumanReport(scope, findings, coverage, trust, verdict, out);
    out.flush();
    bool ok = static_cast<bool>(out);
    out.close();
    return ok ? resultsFile.string() : std::string{};
}

// Writes the full report to <resultsBaseDir>/abyss-results/results.txt and
// prints a short console summary pointing at it; falls back to printing the
// full report directly if the file couldn't be written.
void reportTo(const std::string& resultsBaseDir, const std::string& scope,
             const std::vector<Finding>& findings, const scanner::ScanCoverage& coverage,
             const evidence::RuleTrustStatus& trust, const evidence::Verdict& verdict) {
    std::string path = writeReportFile(resultsBaseDir, scope, findings, coverage, trust, verdict);
    if (path.empty()) {
        std::cout << "(could not write abyss-results/results.txt — showing the full report here instead)\n\n";
        evidence::writeHumanReport(scope, findings, coverage, trust, verdict, std::cout);
        return;
    }
    Severity worst = findings.empty() ? Severity::Info : evidence::maxSeverity(findings);
    std::cout << "Scope: " << sanitizeForOutput(scope) << "\n";
    std::cout << "Verdict: " << verdict.label << " (exit code " << static_cast<int>(verdict.exitCode) << ")\n";
    std::cout << findings.size() << " finding(s)";
    if (!findings.empty()) std::cout << " — highest severity " << toString(worst);
    std::cout << "\n";
    std::cout << "Full report: " << sanitizeForOutput(path) << "\n";
}

// A large project — most commonly node_modules, which is deliberately
// never skipped (a compromised dependency is exactly the attack shape
// this project targets) — can take a real amount of time to analyze file
// by file, with no other output in between "Scanning X..." and the final
// report. Without this, that gap is indistinguishable from a hang. Prints
// to stderr (never stdout, so --json output stays parseable), throttled
// so a fast scan of a small project never prints anything at all.
//
// scanner::scanRepository parallelizes large scans across worker threads
// (see scanner.cpp), each of which calls this concurrently — the mutex
// guards last_/printed_ and serializes the actual writes so progress lines
// from different threads never interleave into garbled output.
class ScanProgressPrinter {
public:
    void operator()(std::size_t analyzed, std::size_t discovered, std::size_t threadsUsed) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::steady_clock::now();
        // The thread count is only known once the first file completes (it
        // depends on file count, CPU cores, and available memory measured
        // at scan start — see scanner.cpp) but announcing it once, as soon
        // as it's known, is what actually answers "is this really running
        // in parallel" rather than just claiming a number in documentation.
        if (!announcedThreads_) {
            std::cerr << (threadsUsed > 1 ? "Analyzing with " + std::to_string(threadsUsed) + " worker threads.\n"
                                          : "Analyzing single-threaded (scan too small, or memory/CPU cores "
                                            "limited it to 1 thread).\n");
            announcedThreads_ = true;
        }
        if (printed_ && now - last_ < std::chrono::milliseconds(300)) return;
        std::cerr << "\r  scanning: " << analyzed << " / " << discovered << " file(s) analyzed"
                  << std::string(10, ' ') << "\r" << std::flush;
        last_ = now;
        printed_ = true;
    }
    ~ScanProgressPrinter() {
        if (printed_) std::cerr << "\r" << std::string(60, ' ') << "\r" << std::flush;
    }

private:
    std::mutex mutex_;
    std::chrono::steady_clock::time_point last_{};
    bool printed_ = false;
    bool announcedThreads_ = false;
};

// Shared by runScan() (one engine load per call) and cmdScanAll() (one
// engine load reused across every project in a parent directory) so
// scanning many projects doesn't reload and re-verify the same rule pack
// from disk once per project.
ScanRun runScanWithEngine(const std::string& path, const LoadedEngine& loaded) {
    ScanRun run;
    run.trust = loaded.trust;
    run.loadErrors = loaded.loadErrors;
    run.rulesDir = loaded.rulesDir;

    ScanProgressPrinter progress;
    scanner::ScanOptions options;
    options.thresholds = loaded.thresholds;
    options.onProgress = std::ref(progress);
    run.report = scanner::scanRepository(path, loaded.ruleEngine, loaded.esr, options);

    // Installed VS Code extensions are host/environment context, not part
    // of the scanned repository — merged into the same report (per the
    // requirement to integrate extension discovery into the actual scan
    // path) but distinguishable by their "vscode-extension:<id>" filePath.
    // Static manifest-shape checks only; see vscode::scanExtensionRecord.
    for (const auto& ext : vscode::discoverExtensions(vscode::defaultExtensionsRoot())) {
        auto extFindings = vscode::scanExtensionRecord(ext);
        run.report.findings.insert(run.report.findings.end(), extFindings.begin(), extFindings.end());
    }

    run.verdict = evidence::computeVerdict(run.report.coverage, run.report.findings, run.trust);
    return run;
}

ScanRun runScan(const std::string& path, const std::string& rulesOverride) {
    return runScanWithEngine(path, loadEngine(rulesOverride));
}

int cmdCheck() {
    std::cout << "Abyss environment check\n";
    std::cout << "========================\n";

    auto loaded = loadEngine("");
    std::cout << "Rules directory:     " << (loaded.rulesDir.empty() ? "NOT FOUND" : loaded.rulesDir) << "\n";
    std::cout << "Rule trust level:    " << loaded.trust.trustLevel << "\n";
    std::cout << "Integrity status:    " << loaded.trust.integrityStatus << "\n";
    if (!loaded.trust.details.empty()) std::cout << "Details:             " << loaded.trust.details << "\n";
    std::cout << "Rules loaded:        " << loaded.ruleEngine.rules().size() << "\n";
    std::cout << "Execution surfaces:  " << loaded.esr.surfaces().size() << "\n";
    for (const auto& e : loaded.loadErrors) std::cout << "  [warn] " << e << "\n";

#if defined(_WIN32)
    std::cout << "SHA-256 provider (BCrypt): ";
    std::uint8_t probe[3] = {'a', 'b', 'c'};
    std::string digest = crypto::sha256Hex(probe, 3);
    std::cout << (digest.size() == 64 ? "OK" : "UNAVAILABLE") << "\n";
#endif

    std::cout << "\nStatic scanning, transactional quarantine, safe Git staging, repository guards,\n";
    std::cout << "and local protection state are available. Host inspection remains fail-closed\n";
    std::cout << "when Windows denies access to requested locations.\n";
    return loaded.trust.degraded ? (int)evidence::ExitCode::OperationalFailure : 0;
}

int cmdScan(const std::string& path, bool jsonOutput, const std::string& rulesOverride) {
    if (!fs::exists(path)) {
        std::cerr << "abyss: path does not exist: " << path << "\n";
        return (int)evidence::ExitCode::OperationalFailure;
    }

    auto run = runScan(path, rulesOverride);

    if (jsonOutput) {
        evidence::writeFindingsJsonl(run.report.findings, std::cout);
        std::cerr << "[trust] " << run.trust.trustLevel << "/" << run.trust.integrityStatus << "\n";
        std::cerr << "[verdict] " << run.verdict.label << " (exit " << (int)run.verdict.exitCode
                   << "): " << run.verdict.explanation << "\n";
    } else {
        reportTo(path, fs::absolute(path).string(), run.report.findings, run.report.coverage,
                run.trust, run.verdict);
    }

    return (int)run.verdict.exitCode;
}

int cmdSystemScan(bool jsonOutput, const std::string& rulesOverride) {
    auto discovery = response::discoverHostTargets();
    auto loaded = loadEngine(rulesOverride);
    scanner::ScanReport combined;
    combined.coverage.directoryErrors = discovery.errors.size();
    for (const auto& target : discovery.targets) {
        std::cerr << "Scanning " << sanitizeForOutput(target.path) << "...\n";
        ScanProgressPrinter progress;
        scanner::ScanOptions options;
        options.thresholds = loaded.thresholds;
        options.onProgress = std::ref(progress);
        auto report = scanner::scanRepository(target.path, loaded.ruleEngine, loaded.esr, options);
        combined.findings.insert(combined.findings.end(), report.findings.begin(), report.findings.end());
        combined.coverage.filesDiscovered += report.coverage.filesDiscovered;
        combined.coverage.filesAnalyzed += report.coverage.filesAnalyzed;
        combined.coverage.filesTruncated += report.coverage.filesTruncated;
        combined.coverage.filesUnreadable += report.coverage.filesUnreadable;
        combined.coverage.symlinkEscapesSkipped += report.coverage.symlinkEscapesSkipped;
        combined.coverage.directoryErrors += report.coverage.directoryErrors;
        combined.coverage.filesChangedDuringScan += report.coverage.filesChangedDuringScan;
        combined.coverage.gitDetected = combined.coverage.gitDetected || report.coverage.gitDetected;
    }
    auto persistence = response::inspectPersistence();
    combined.findings.insert(combined.findings.end(), persistence.begin(), persistence.end());
    for (const auto& ext : vscode::discoverExtensions(vscode::defaultExtensionsRoot())) {
        auto extFindings = vscode::scanExtensionRecord(ext);
        combined.findings.insert(combined.findings.end(), extFindings.begin(), extFindings.end());
    }
    auto verdict = evidence::computeVerdict(combined.coverage, combined.findings, loaded.trust);
    if (jsonOutput) {
        evidence::writeFindingsJsonl(combined.findings, std::cout);
        std::cerr << "[targets] " << discovery.targets.size() << " repository/repositories\n";
        std::cerr << "[verdict] " << verdict.label << " (exit " << static_cast<int>(verdict.exitCode) << ")\n";
    } else {
        std::cout << "Discovered repositories: " << discovery.targets.size() << "\n";
        for (const auto& target : discovery.targets) std::cout << "  " << sanitizeForOutput(target.path) << "\n";
        for (const auto& error : discovery.errors) std::cout << "  [coverage] " << sanitizeForOutput(error) << "\n";
        std::cout << "\n";
        reportTo(response::defaultStateRoot(), "developer repositories and persistence locations on this PC",
                combined.findings, combined.coverage, loaded.trust, verdict);
    }
    return static_cast<int>(verdict.exitCode);
}

void printRemediationPlan(const response::RemediationPlan& plan) {
    std::size_t eligible = 0;
    std::cout << "ABYSS REMEDIATION PLAN\n======================\n";
    std::cout << "Scope: " << sanitizeForOutput(plan.scanRoot) << "\n\n";
    for (const auto& action : plan.actions) {
        if (action.eligible) {
            ++eligible;
            std::cout << "  QUARANTINE " << sanitizeForOutput(action.sourcePath) << "\n"
                      << "    rule: " << sanitizeForOutput(action.ruleId) << "\n";
        } else {
            std::cout << "  REVIEW " << sanitizeForOutput(action.ruleId) << " — "
                      << sanitizeForOutput(action.refusal) << "\n";
        }
    }
    std::cout << "\nEligible confirmed actions: " << eligible << "\n";
}

int cmdRemediate(const std::string& path, const std::string& rulesOverride,
                 bool confirmed, bool verifyOnly) {
    if (!fs::exists(path)) {
        std::cerr << "abyss: path does not exist: " << path << "\n";
        return static_cast<int>(evidence::ExitCode::OperationalFailure);
    }
    auto before = runScan(path, rulesOverride);
    if (verifyOnly) {
        reportTo(path, fs::absolute(path).string(), before.report.findings, before.report.coverage,
                before.trust, before.verdict);
        if (before.verdict.label == "ALLOW") std::cout << "Verification result: VERIFIED for the requested scope.\n";
        return static_cast<int>(before.verdict.exitCode);
    }

    auto plan = response::buildPlan(path, before.report.findings);
    printRemediationPlan(plan);
    if (!confirmed) {
        std::cout << "\nDry run only. Review the plan and repeat with --yes to apply eligible actions.\n";
        // A dry run changes nothing, so it reports the scan's own verdict
        // exit code directly (BLOCK/REVIEW/INCOMPLETE/ALLOW) rather than a
        // flat "Unresolved" whenever findings exist — that used to discard
        // whether the underlying result was BLOCK or REVIEW for no reason;
        // nothing was attempted yet, so "unresolved after an action" isn't
        // the right claim to make here.
        return static_cast<int>(before.verdict.exitCode);
    }
    auto result = response::applyPlan(plan, response::defaultStateRoot(), true);
    for (const auto& rec : result.quarantined)
        std::cout << "Quarantined " << sanitizeForOutput(rec.originalPath) << " as " << rec.id << "\n";
    for (const auto& skipped : result.skipped) std::cout << "Review required: " << sanitizeForOutput(skipped) << "\n";
    for (const auto& error : result.errors) std::cerr << "[error] " << sanitizeForOutput(error) << "\n";
    if (!result.errors.empty()) return static_cast<int>(evidence::ExitCode::Unresolved);

    if (result.quarantined.empty()) {
        // Nothing was actually eligible for automatic quarantine (every
        // finding needs Critical severity AND Confirmed confidence — see
        // response::buildPlan) — no file was touched, so the project's
        // verdict is exactly what it was before this command ran. Reporting
        // that as "UNRESOLVED" would claim an action was attempted and
        // failed to fully resolve things, which is a different and
        // misleading claim from "there was nothing this command could do
        // automatically." Returns the unchanged verdict's own exit code —
        // still BLOCK if it was BLOCK, not a flattened "unresolved".
        std::cout << "\nNo findings were eligible for automatic quarantine. Every finding above needs\n"
                     "manual review; the project's verdict is unchanged.\n";
        return static_cast<int>(before.verdict.exitCode);
    }

    auto after = runScan(path, rulesOverride);
    std::cout << "\nPOST-REMEDIATION VERIFICATION\n=============================\n";
    reportTo(path, fs::absolute(path).string(), after.report.findings, after.report.coverage,
            after.trust, after.verdict);
    if (after.verdict.label == "ALLOW") return 0;
    // Something genuinely was quarantined above, and the project still
    // isn't clean after that real change — this is the case UNRESOLVED
    // actually describes: a requested action was taken and didn't reach a
    // verified end state, as distinct from "nothing was eligible" above.
    return static_cast<int>(evidence::ExitCode::Unresolved);
}

int cmdQuarantineList() {
    std::vector<std::string> errors;
    auto records = response::listQuarantine(response::defaultStateRoot(), &errors);
    std::cout << "ABYSS QUARANTINE\n================\n";
    for (const auto& rec : records) {
        std::cout << rec.id << "  " << (rec.restored ? "RESTORED" : "ACTIVE") << "  "
                  << sanitizeForOutput(rec.originalPath) << "  " << rec.sha256 << "\n";
    }
    if (records.empty()) std::cout << "No quarantine records.\n";
    for (const auto& error : errors) std::cerr << "[error] " << sanitizeForOutput(error) << "\n";
    return errors.empty() ? 0 : static_cast<int>(evidence::ExitCode::OperationalFailure);
}

int cmdQuarantineRestore(const std::string& id, bool force) {
    std::string error;
    if (!response::restoreQuarantine(response::defaultStateRoot(), id, force, error)) {
        std::cerr << "Restore failed: " << sanitizeForOutput(error) << "\n";
        return static_cast<int>(evidence::ExitCode::OperationalFailure);
    }
    std::cout << "Quarantine record " << sanitizeForOutput(id) << " restored. Scan the destination before executing it.\n";
    return 0;
}

int cmdPreflight(const std::string& path, const std::string& rulesOverride) {
    if (!fs::exists(path)) {
        std::cerr << "abyss: path does not exist: " << path << "\n";
        return (int)evidence::ExitCode::OperationalFailure;
    }
    auto run = runScan(path, rulesOverride);

    std::cout << "ABYSS PREFLIGHT\n===============\n";
    std::cout << "Target: " << sanitizeForOutput(fs::absolute(path).string()) << "\n\n";

    // The decision IS the verdict's own label — ALLOW / REVIEW / BLOCK /
    // INCOMPLETE — never collapsed into a two-state allow/block boolean.
    // REVIEW in particular must never be presented as an unconditional
    // ALLOW (High-severity findings still need a human to look at them).
    std::cout << "Decision: " << run.verdict.label << "\n";
    std::cout << "Detail:   " << run.verdict.explanation << "\n\n";

    if (run.verdict.label == "BLOCK" || run.verdict.label == "INCOMPLETE") {
        std::cout << "Do not open this folder in an editor or run its build tooling until reviewed.\n";
    } else if (run.verdict.label == "REVIEW") {
        std::cout << "Findings require manual review before proceeding — this is not a clean ALLOW.\n";
    } else {
        std::cout << "No findings within available evidence. Coverage is complete for this run.\n";
    }
    return (int)run.verdict.exitCode;
}

int cmdOpen(const std::string& path, const std::string& rulesOverride) {
    if (!fs::exists(path)) {
        std::cerr << "abyss: path does not exist: " << path << "\n";
        return (int)evidence::ExitCode::OperationalFailure;
    }
    auto run = runScan(path, rulesOverride);

    std::cout << "ABYSS OPEN — preflight gate\n===========================\n";
    std::cout << "Target: " << sanitizeForOutput(fs::absolute(path).string()) << "\n\n";
    std::cout << "Decision: " << run.verdict.label << "\n";
    std::cout << "Detail:   " << run.verdict.explanation << "\n\n";

    if (run.verdict.label == "BLOCK" || run.verdict.label == "INCOMPLETE") {
        std::cout << "Refusing to recommend opening this folder in an editor.\n";
    } else if (run.verdict.label == "REVIEW") {
        std::cout << "Findings require manual review. Abyss will not launch the project.\n";
    } else {
        std::cout << "Preflight passed. Open the project with your normal editor.\n";
    }
    return (int)run.verdict.exitCode;
}

int cmdRulesList(const std::string& rulesOverride) {
    auto loaded = loadEngine(rulesOverride);
    std::cout << "Rules directory: " << (loaded.rulesDir.empty() ? "NOT FOUND" : loaded.rulesDir) << "\n";
    std::cout << "Trust: " << loaded.trust.trustLevel << "/" << loaded.trust.integrityStatus << "\n\n";
    for (const auto& r : loaded.ruleEngine.rules()) {
        std::cout << "[" << toString(r.type) << "/" << toString(r.severity) << "] " << r.id << " — " << r.name;
        if (!r.campaign.empty()) std::cout << " (campaign: " << r.campaign << ")";
        std::cout << "\n";
    }
    std::cout << "\nExecution Surface Registry:\n";
    for (const auto& s : loaded.esr.surfaces()) {
        std::cout << "  " << s.id << " (" << s.tool << ") — " << s.patterns.size() << " pattern(s), risk="
                  << s.risk << "\n";
    }
    for (const auto& e : loaded.loadErrors) std::cerr << "[warn] " << e << "\n";
    return loaded.trust.degraded ? (int)evidence::ExitCode::OperationalFailure : 0;
}

int cmdRulesVerify(const std::string& rulesOverride) {
    std::string dir = !rulesOverride.empty() ? rulesOverride : findOfficialRulesDirectory();
    std::cout << "Abyss rule pack integrity verification\n=======================================\n";
    std::cout << "Rules directory: " << (dir.empty() ? "NOT FOUND" : dir) << "\n\n";
    if (dir.empty()) {
        std::cout << "No official rule pack found in any trusted installation location.\n";
        return (int)evidence::ExitCode::OperationalFailure;
    }

    auto v = rules::verifyRuleManifest(dir);
    if (!v.manifestFound) {
        std::cout << "No MANIFEST.sha256 present in this directory — integrity is unverified.\n";
        std::cout << "Run tools/generate_rules_manifest.ps1 to generate one (maintainer/release step).\n";
        return (int)evidence::ExitCode::OperationalFailure;
    }

    for (const auto& m : v.mismatches) std::cout << "  MISMATCH:  " << m << "\n";
    for (const auto& u : v.untracked) std::cout << "  UNTRACKED: " << u << " (present on disk, not in manifest)\n";

    if (v.allVerified) {
        std::cout << "All rule/ESR files verified against MANIFEST.sha256.\n";
        return 0;
    }
    std::cout << "\nIntegrity check FAILED — the rule pack may have been tampered with after installation.\n";
    return (int)evidence::ExitCode::Blocked;
}

// A predictable staging directory name (e.g. a fixed "abyss_self_scan_stage")
// under a shared temp directory is pre-creatable/symlinkable by another
// principal on a multi-user system. Mixing the process ID with random bits
// makes the path unpredictable in advance of the run that creates it.
std::string uniqueTempDirName(const std::string& prefix) {
    std::random_device rd;
    std::uniform_int_distribution<std::uint64_t> dist;
    std::uint64_t r1 = dist(rd), r2 = dist(rd);
    std::ostringstream oss;
#if defined(_WIN32)
    const auto pid = static_cast<unsigned long>(GetCurrentProcessId());
#else
    const auto pid = static_cast<unsigned long>(getpid());
#endif
    oss << prefix << "_" << pid << "_" << std::hex << r1 << r2;
    return oss.str();
}

int cmdSelfScan() {
    // Scans a staged copy of *only abyss.exe*, not the raw build/exe
    // directory and not the rule pack. A build tree additionally contains
    // .obj/.pdb files, the test binary, and CMake metadata that are not
    // part of what Abyss actually ships. The rule pack is deliberately
    // excluded from the scan target for a different reason: rule files
    // intentionally contain the literal IOC strings, obfuscation shapes,
    // and campaign markers they exist to detect, so treating them as
    // ordinary scan input would trip Abyss's own heuristics against its
    // own detection data — a self-referential false positive, not a real
    // finding. The rule pack's integrity is verified separately, by hash
    // (see `abyss check` / `abyss rules verify`), not by content-scanning it.
    std::string exeDir = exeDirectory();
    std::error_code ec;
    fs::path stageDir = fs::temp_directory_path() / uniqueTempDirName("abyss_self_scan_stage");
    fs::remove_all(stageDir, ec);
    fs::create_directories(stageDir, ec);

    bool staged = false;
    fs::path exePath = fs::path(exeDir) / "abyss.exe";
    if (fs::exists(exePath, ec)) {
        fs::copy_file(exePath, stageDir / "abyss.exe", ec);
        staged = !ec;
    }

    std::string target = staged ? stageDir.string() : exeDir;
    std::cout << "Abyss self-scan\n================\n";
    std::cout << "Scanning installation layout: " << sanitizeForOutput(target) << "\n";
    if (staged) {
        std::cout << "(a staged copy of abyss.exe; the official rule pack is integrity-verified\n"
                      "separately and supplies detection logic, but is not scanned as hostile input)\n";
    } else {
        std::cout << "(could not stage abyss.exe — falling back to scanning the executable's own "
                      "directory as-is)\n";
    }
    std::cout << "\n";

    auto run = runScan(target, "");
    // Report against exeDir, not the staged copy: the staging directory is
    // deleted below, so a results file written there would vanish with it.
    reportTo(exeDir, target, run.report.findings, run.report.coverage, run.trust, run.verdict);

    fs::remove_all(stageDir, ec);
    return (int)run.verdict.exitCode;
}

int verdictPriority(evidence::ExitCode code) {
    switch (code) {
        case evidence::ExitCode::Blocked: return 5;
        case evidence::ExitCode::Unresolved: return 4;
        case evidence::ExitCode::OperationalFailure: return 3;
        case evidence::ExitCode::SuspiciousReview: return 2;
        case evidence::ExitCode::Clean: return 1;
    }
    return 3;
}

bool hasCredentialExposure(const std::vector<Finding>& findings) {
    return std::any_of(findings.begin(), findings.end(), [](const Finding& finding) {
        return std::find(finding.tags.begin(), finding.tags.end(), "credential-exposure") != finding.tags.end();
    });
}

void printCredentialRecoveryChecklist() {
    std::cout <<
        "\nCREDENTIAL RECOVERY\n"
        "===================\n"
        "Abyss never prints, uploads or revokes credential values. If this project or PC\n"
        "was infected, assume credentials used on it may have been copied. From a clean\n"
        "device after containment:\n\n"
        "  1. GitHub: sign out unknown sessions and rotate personal access tokens.\n"
        "  2. Review GitHub SSH keys, deploy keys, GitHub Apps and OAuth applications.\n"
        "  3. Replace GitHub Actions secrets and inspect self-hosted runners.\n"
        "  4. Revoke npm tokens and review recent package publishing activity.\n"
        "  5. Rotate exposed cloud keys, database passwords and API credentials.\n"
        "  6. Remove committed secrets from Git history; rotation is still required.\n"
        "  7. Create replacement credentials only after this PC and project verify clean.\n";
}

// Guards against `scan-all` recursively scanning Abyss's own installation
// directory when it happens to live inside the parent folder being scanned
// (e.g. a developer keeps `E:\Big Projects\Abyss\` alongside their other
// projects and runs `scan-all E:\Big Projects`).
bool isAbyssToolDirectory(const fs::path& candidate, const fs::path& ownDirectory) {
    if (!ownDirectory.empty() && candidate == ownDirectory) return true;

    std::string directoryName = candidate.filename().string();
    std::transform(directoryName.begin(), directoryName.end(), directoryName.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    if (directoryName != "abyss") return false;

    std::error_code ec;
    return fs::is_regular_file(candidate / "abyss.exe", ec);
}

int cmdScanAll(const std::string& parent, const std::string& rulesOverride, bool confirmed) {
    std::error_code ec;
    fs::path parentPath = fs::weakly_canonical(parent, ec);
    if (ec || !fs::is_directory(parentPath, ec)) {
        std::cerr << "abyss scan-all: parent directory is not readable: " << sanitizeForOutput(parent) << "\n";
        return static_cast<int>(evidence::ExitCode::OperationalFailure);
    }
    fs::path ownDirectory = fs::weakly_canonical(exeDirectory(), ec);
    ec.clear();

    // Loaded once and reused for every project below — cmdScanAll can cover
    // dozens of projects in one run, and re-verifying the same on-disk rule
    // pack (hashing every rule file again) for each one would make a large
    // scan-all needlessly slow without changing any result.
    auto loaded = loadEngine(rulesOverride);

    struct ProjectResult { std::string label; std::string path; std::string verdict; };
    std::vector<ProjectResult> projects;
    evidence::ExitCode finalCode = evidence::ExitCode::Clean;
    bool credentialRisk = false;

    std::cout << "ABYSS MULTI-PROJECT SCAN\n========================\n";
    std::cout << "Parent: " << sanitizeForOutput(parentPath.string()) << "\n\n";
    for (fs::directory_iterator it(parentPath, fs::directory_options::skip_permission_denied, ec), end;
         it != end; it.increment(ec)) {
        if (ec) { std::cerr << "[coverage] " << sanitizeForOutput(ec.message()) << "\n"; ec.clear(); continue; }
        if (it->is_symlink(ec) || isReparsePoint(it->path()) || !it->is_directory(ec)) continue;
        fs::path candidate = fs::weakly_canonical(it->path(), ec);
        if (ec) { ec.clear(); continue; }
        if (isAbyssToolDirectory(candidate, ownDirectory)) {
            projects.push_back({candidate.filename().string(), {}, "SKIPPED TOOL DIRECTORY"});
            continue;
        }
        std::cout << "Scanning " << sanitizeForOutput(candidate.filename().string()) << "...\n";
        auto run = runScanWithEngine(candidate.string(), loaded);
        credentialRisk = credentialRisk || hasCredentialExposure(run.report.findings);
        projects.push_back({candidate.filename().string(), candidate.string(), run.verdict.label});
        if (verdictPriority(run.verdict.exitCode) > verdictPriority(finalCode)) finalCode = run.verdict.exitCode;
        if (run.verdict.label != "ALLOW") {
            reportTo(candidate.string(), candidate.string(), run.report.findings, run.report.coverage,
                    run.trust, run.verdict);
            std::cout << "\n";
        }
    }

    // Scan loose files such as *.code-workspace stored directly in the
    // parent without descending through project directories or the tool.
    fs::path looseStage = fs::temp_directory_path() / uniqueTempDirName("abyss_parent_files");
    fs::create_directories(looseStage, ec);
    std::size_t looseFiles = 0;
    if (!ec) {
        for (fs::directory_iterator it(parentPath, fs::directory_options::skip_permission_denied, ec), end;
             it != end; it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (!it->is_regular_file(ec) || it->is_symlink(ec) || isReparsePoint(it->path())) continue;
            fs::copy_file(it->path(), looseStage / it->path().filename(), fs::copy_options::none, ec);
            if (!ec) ++looseFiles;
            ec.clear();
        }
    }
    bool looseFilesBlocked = false;
    if (looseFiles > 0) {
        auto loose = runScanWithEngine(looseStage.string(), loaded);
        credentialRisk = credentialRisk || hasCredentialExposure(loose.report.findings);
        projects.push_back({"files stored directly in parent", {}, loose.verdict.label});
        looseFilesBlocked = loose.verdict.label == "BLOCK";
        if (verdictPriority(loose.verdict.exitCode) > verdictPriority(finalCode)) finalCode = loose.verdict.exitCode;
        if (loose.verdict.label != "ALLOW") {
            reportTo(parentPath.string(), parentPath.string() + " direct files", loose.report.findings,
                    loose.report.coverage, loose.trust, loose.verdict);
            std::cout << "\n";
        }
    }
    fs::remove_all(looseStage, ec);

    std::cout << "\nSCAN SUMMARY\n============\n";
    for (const auto& project : projects)
        std::cout << "  " << sanitizeForOutput(project.label, 200) << ": " << project.verdict << "\n";
    std::cout << "\nFinal result: " << evidence::toString(finalCode)
              << " (exit " << static_cast<int>(finalCode) << ")\n";
    std::cout << "Detailed findings for any non-ALLOW project above were saved to that project's own\n"
                 "abyss-results\\results.txt, not printed here.\n";

    std::vector<std::string> blockedPaths;
    for (const auto& project : projects) {
        if (project.verdict == "BLOCK" && !project.path.empty()) blockedPaths.push_back(project.path);
    }

    if (!blockedPaths.empty() && confirmed) {
        std::cout << "\nCLEANING " << blockedPaths.size() << " BLOCKED PROJECT(S)\n"
                  << std::string(24, '=') << "\n";
        for (const auto& projectPath : blockedPaths) {
            std::cout << "\n--- " << sanitizeForOutput(projectPath) << " ---\n";
            cmdRemediate(projectPath, rulesOverride, true, false);
        }
        if (looseFilesBlocked) {
            std::cout << "\nFiles stored directly in " << sanitizeForOutput(parentPath.string())
                      << " were BLOCKED but are not auto-cleaned by scan-all — run `abyss contain \""
                      << sanitizeForOutput(parentPath.string()) << "\"` to review and quarantine them.\n";
        }
        std::cout << "\nRun `abyss scan-all \"" << sanitizeForOutput(parentPath.string())
                  << "\"` again to confirm every project now reaches ALLOW.\n";
    } else if (finalCode != evidence::ExitCode::Clean) {
        std::cout << "\nNEXT ACTION\n===========\n";
        if (!blockedPaths.empty()) {
            std::cout << "Re-run with --yes (or answer YES when the interactive menu asks) to quarantine\n"
                         "confirmed evidence in every BLOCKED project above in one pass — each project\n"
                         "still gets its own plan shown and a post-remediation rescan.\n";
        }
        std::cout << "Run `abyss contain <path>` for any REVIEW project above: heuristic findings are\n"
                     "never auto-quarantined and need a human decision.\n";
    }
    if (finalCode == evidence::ExitCode::Blocked || credentialRisk) printCredentialRecoveryChecklist();
    return static_cast<int>(finalCode);
}

int cmdClone(const std::string& remote, const std::string& destination,
             const std::string& rulesOverride) {
    auto staged = git::prepareClone(remote, destination);
    if (!staged.ok) {
        // redactSecrets() first: a clone URL with embedded HTTP basic-auth
        // credentials (https://user:token@host/repo.git) can come back
        // verbatim in git's own failure output, and this is printed
        // directly rather than going through reportTo()'s report file.
        std::cerr << "Safe clone staging failed: " << sanitizeForOutput(redactSecrets(staged.error)) << "\n"
                  << sanitizeForOutput(redactSecrets(staged.output)) << "\n";
        return static_cast<int>(evidence::ExitCode::OperationalFailure);
    }
    auto scan = runScan(staged.stagePath, rulesOverride);
    reportTo(staged.stagePath, staged.stagePath, scan.report.findings, scan.report.coverage,
            scan.trust, scan.verdict);
    std::string message;
    const bool allow = scan.verdict.label == "ALLOW";
    const bool published = git::finalizeClone(staged, destination, allow, message);
    std::cout << sanitizeForOutput(message) << "\n";
    return published ? 0 : static_cast<int>(scan.verdict.exitCode);
}

int cmdPull(const std::string& repository, const std::string& rulesOverride) {
    auto current = runScan(repository, rulesOverride);
    if (current.verdict.label != "ALLOW") {
        reportTo(repository, repository, current.report.findings, current.report.coverage,
                current.trust, current.verdict);
        std::cerr << "Pull refused because the existing repository did not pass preflight.\n";
        return static_cast<int>(current.verdict.exitCode);
    }
    auto staged = git::preparePull(repository);
    if (!staged.ok) {
        std::cerr << "Safe pull staging failed: " << sanitizeForOutput(redactSecrets(staged.error)) << "\n"
                  << sanitizeForOutput(redactSecrets(staged.output)) << "\n";
        return static_cast<int>(evidence::ExitCode::OperationalFailure);
    }
    auto incoming = runScan(staged.stagePath, rulesOverride);
    // Reported against `repository`, not staged.stagePath: on ALLOW,
    // finalizePull removes the staging worktree below, which would take a
    // results file written there with it.
    reportTo(repository, staged.stagePath, incoming.report.findings, incoming.report.coverage,
            incoming.trust, incoming.verdict);
    std::string message;
    const bool allow = incoming.verdict.label == "ALLOW";
    const bool merged = git::finalizePull(repository, staged, allow, message);
    std::cout << sanitizeForOutput(message) << "\n";
    return merged ? 0 : static_cast<int>(incoming.verdict.exitCode);
}

int cmdTimeline(const std::string& repository, bool drawGraph) {
    auto result = drawGraph ? git::graph(repository) : git::timeline(repository);
    if (!result.started || result.timedOut || result.exitCode != 0) {
        std::cerr << (drawGraph ? "Graph" : "Timeline") << " collection failed: "
                  << sanitizeForOutput(redactSecrets(result.error.empty() ? result.output : result.error)) << "\n";
        return static_cast<int>(evidence::ExitCode::OperationalFailure);
    }
    std::cout << (drawGraph ? "ABYSS GIT GRAPH\n===============\n" : "ABYSS GIT TIMELINE\n==================\n");
    // redactSecrets(): commit subjects/author identities are repository
    // content (not scanned by the file-based credential detector, since
    // this is Git metadata, not a file), and could contain a credential a
    // developer accidentally pasted into a commit message.
    std::cout << sanitizeForOutput(redactSecrets(result.output), 8 * 1024 * 1024) << "\n";
    return 0;
}

int cmdRecover(const std::string& repository, const std::string& commit,
               const std::string& destination, const std::string& rulesOverride) {
    auto staged = git::prepareRecovery(repository, commit, destination);
    if (!staged.ok) {
        std::cerr << "Recovery staging failed: " << sanitizeForOutput(redactSecrets(staged.error)) << "\n";
        return static_cast<int>(evidence::ExitCode::OperationalFailure);
    }
    auto scan = runScan(staged.stagePath, rulesOverride);
    reportTo(staged.stagePath, staged.stagePath, scan.report.findings, scan.report.coverage,
            scan.trust, scan.verdict);
    if (scan.verdict.label != "ALLOW") {
        std::cerr << "The selected commit was materialized for evidence but is not a verified recovery point.\n";
        return static_cast<int>(evidence::ExitCode::Unresolved);
    }
    std::cout << "Verified recovery worktree created at " << sanitizeForOutput(destination)
              << ". The original branch and remote history were not rewritten.\n";
    return 0;
}

#if defined(_WIN32)
SERVICE_STATUS_HANDLE g_serviceStatusHandle = nullptr;
HANDLE g_serviceStopEvent = nullptr;

void setServiceState(DWORD state, DWORD exitCode = NO_ERROR) {
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwWin32ExitCode = exitCode;
    status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    SetServiceStatus(g_serviceStatusHandle, &status);
}

DWORD WINAPI serviceControl(DWORD control, DWORD, void*, void*) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        setServiceState(SERVICE_STOP_PENDING);
        if (g_serviceStopEvent) SetEvent(g_serviceStopEvent);
    }
    return NO_ERROR;
}

void appendProtectionAudit(const std::string& text) {
    std::error_code ec;
    fs::create_directories(response::defaultStateRoot(), ec);
    std::ofstream out(fs::path(response::defaultStateRoot()) / "protection.log",
                      std::ios::binary | std::ios::app);
    if (out) out << text << "\n";
}

void WINAPI serviceMain(DWORD, LPSTR*) {
    g_serviceStatusHandle = RegisterServiceCtrlHandlerExA("AbyssProtection", serviceControl, nullptr);
    if (!g_serviceStatusHandle) return;
    g_serviceStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_serviceStopEvent) { setServiceState(SERVICE_STOPPED, GetLastError()); return; }
    setServiceState(SERVICE_RUNNING);
    while (WaitForSingleObject(g_serviceStopEvent, 5000) == WAIT_TIMEOUT) {
        auto roots = response::protectedRoots(response::defaultStateRoot(), nullptr);
        for (const auto& root : roots) {
            auto run = runScan(root, "");
            if (run.verdict.label == "BLOCK") {
                auto plan = response::buildPlan(root, run.report.findings);
                auto remediated = response::applyPlan(plan, response::defaultStateRoot(), true);
                appendProtectionAudit("BLOCK " + root + " quarantined=" +
                                      std::to_string(remediated.quarantined.size()) +
                                      " errors=" + std::to_string(remediated.errors.size()));
            } else if (run.verdict.label != "ALLOW") {
                appendProtectionAudit(run.verdict.label + " " + root);
            }
        }
    }
    CloseHandle(g_serviceStopEvent); g_serviceStopEvent = nullptr;
    setServiceState(SERVICE_STOPPED);
}

bool installProtectionService(std::string& error) {
    char exe[MAX_PATH]{};
    if (!GetModuleFileNameA(nullptr, exe, MAX_PATH)) { error = "cannot resolve abyss.exe path"; return false; }
    std::string command = "\"" + std::string(exe) + "\" service";
    SC_HANDLE manager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!manager) { error = "administrator access is required to install the protection service"; return false; }
    SC_HANDLE service = CreateServiceA(manager, "AbyssProtection", "Abyss Developer Protection",
        SERVICE_START | SERVICE_QUERY_STATUS | DELETE, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!service && GetLastError() == ERROR_SERVICE_EXISTS)
        service = OpenServiceA(manager, "AbyssProtection", SERVICE_START | SERVICE_QUERY_STATUS | DELETE);
    if (!service) { CloseServiceHandle(manager); error = "cannot create or open AbyssProtection service"; return false; }
    if (!StartServiceA(service, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        error = "service was installed but could not be started";
        CloseServiceHandle(service); CloseServiceHandle(manager); return false;
    }
    CloseServiceHandle(service); CloseServiceHandle(manager); return true;
}

bool removeProtectionService(std::string& error) {
    SC_HANDLE manager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) { error = "cannot open Service Control Manager"; return false; }
    SC_HANDLE service = OpenServiceA(manager, "AbyssProtection", SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!service) {
        DWORD code = GetLastError(); CloseServiceHandle(manager);
        if (code == ERROR_SERVICE_DOES_NOT_EXIST) return true;
        error = "cannot open AbyssProtection service"; return false;
    }
    SERVICE_STATUS status{}; ControlService(service, SERVICE_CONTROL_STOP, &status);
    bool ok = DeleteService(service) != FALSE || GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE;
    if (!ok) error = "cannot remove AbyssProtection service";
    CloseServiceHandle(service); CloseServiceHandle(manager); return ok;
}

int runAsService() {
    SERVICE_TABLE_ENTRYA table[] = {{const_cast<LPSTR>("AbyssProtection"), serviceMain}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherA(table)) return static_cast<int>(evidence::ExitCode::OperationalFailure);
    return 0;
}
#else
bool installProtectionService(std::string& error) { error = "persistent service installation is available in Windows releases"; return false; }
bool removeProtectionService(std::string&) { return true; }
int runAsService() { return static_cast<int>(evidence::ExitCode::OperationalFailure); }
#endif

int cmdProtect(const std::string& root) {
    std::error_code rootEc;
    if (!fs::is_directory(root, rootEc)) {
        std::cerr << "Protection requires an existing project directory: " << sanitizeForOutput(root) << "\n";
        return static_cast<int>(evidence::ExitCode::OperationalFailure);
    }
    // The protection service quarantines Critical+Confirmed findings on its
    // own five-second poll — enabling it on an already-infected project
    // would trigger that silently on the next cycle instead of through a
    // reviewed `remediate --yes`. Requiring ALLOW first keeps remediation
    // an explicit, visible action.
    auto preflight = runScan(root, "");
    if (preflight.verdict.label != "ALLOW") {
        reportTo(root, fs::absolute(root).string(), preflight.report.findings,
                preflight.report.coverage, preflight.trust, preflight.verdict);
        std::cerr << "Protection refused until this project reaches ALLOW. Clean or review it first.\n";
        return static_cast<int>(preflight.verdict.exitCode);
    }
    std::string error;
    if (!installProtectionService(error)) {
        std::cerr << "Persistent service failed: " << sanitizeForOutput(error) << "\n";
#if defined(_WIN32)
        std::cerr << "Right-click abyss.exe, choose Run as administrator, then select protection again.\n";
#endif
        return static_cast<int>(evidence::ExitCode::OperationalFailure);
    }
    if (!response::addProtectedRoot(response::defaultStateRoot(), root, error)) {
        std::string serviceError;
        removeProtectionService(serviceError);
        std::cerr << "Protection configuration failed: " << sanitizeForOutput(error) << "\n";
        return static_cast<int>(evidence::ExitCode::OperationalFailure);
    }
    std::vector<std::string> messages;
    if (fs::is_directory(fs::path(root) / ".git") &&
        !response::installRepositoryGuards(root, (fs::path(exeDirectory()) / "abyss.exe").string(), messages, error)) {
        std::string rollbackError;
        response::removeProtectedRoot(response::defaultStateRoot(), root, rollbackError);
        if (response::protectedRoots(response::defaultStateRoot(), nullptr).empty()) removeProtectionService(rollbackError);
        std::cerr << "Repository guards failed: " << sanitizeForOutput(error) << "\n";
        return static_cast<int>(evidence::ExitCode::OperationalFailure);
    }
    for (const auto& message : messages) std::cout << sanitizeForOutput(message) << "\n";
    std::cout << "Protection enabled for " << sanitizeForOutput(fs::absolute(root).string()) << ".\n";
    return 0;
}

int cmdUnprotect(const std::string& root) {
    std::string error;
    if (!response::removeProtectedRoot(response::defaultStateRoot(), root, error)) {
        std::cerr << "Cannot update protection state: " << sanitizeForOutput(error) << "\n";
        return static_cast<int>(evidence::ExitCode::OperationalFailure);
    }
    std::vector<std::string> messages;
    if (fs::is_directory(fs::path(root) / ".git") &&
        !response::removeRepositoryGuards(root, (fs::path(exeDirectory()) / "abyss.exe").string(), messages, error)) {
        std::cerr << "Protection state was removed but Git guard cleanup failed: " << sanitizeForOutput(error) << "\n";
        return static_cast<int>(evidence::ExitCode::OperationalFailure);
    }
    for (const auto& message : messages) std::cout << sanitizeForOutput(message) << "\n";
    auto roots = response::protectedRoots(response::defaultStateRoot(), nullptr);
    if (roots.empty() && !removeProtectionService(error)) {
        std::cerr << "Protection state was cleared but service removal failed: " << sanitizeForOutput(error) << "\n";
        return static_cast<int>(evidence::ExitCode::OperationalFailure);
    }
    std::cout << "Protection removed for " << sanitizeForOutput(root)
              << ". Quarantine and audit evidence were preserved.\n";
    return 0;
}

int cmdStatus() {
    std::cout << "Abyss protection status\n========================\n";
    std::vector<std::string> errors;
    auto roots = response::protectedRoots(response::defaultStateRoot(), &errors);
    std::cout << "State: " << (roots.empty() ? "UNPROTECTED" : "PROTECTED") << "\n";
    std::cout << "Protected roots: " << roots.size() << "\n";
    for (const auto& root : roots) std::cout << "  " << sanitizeForOutput(root) << "\n";
    for (const auto& error : errors) std::cerr << "[error] " << sanitizeForOutput(error) << "\n";
    return errors.empty() ? 0 : static_cast<int>(evidence::ExitCode::OperationalFailure);
}

// ---------------------------------------------------------------------------
// Interactive menu — launched when abyss.exe is run with no arguments (e.g.
// double-clicked from Explorer), for developers who would not otherwise use
// a command line. Every action here calls the exact same cmd*() functions
// the CLI commands use; this is a front end, not a second implementation.
// ---------------------------------------------------------------------------

std::string askPath(const std::string& label, const std::string& defaultPath = {}) {
    std::cout << label;
    if (!defaultPath.empty()) std::cout << " [" << sanitizeForOutput(defaultPath) << "]";
    std::cout << ": ";
    std::string value;
    std::getline(std::cin, value);
    value = trim(value);
    if (value.empty()) return defaultPath;
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
        value = value.substr(1, value.size() - 2);
    return value;
}

void pauseMenu() {
    std::cout << "\nPress Enter to return to the menu...";
    std::string ignored;
    std::getline(std::cin, ignored);
}

void runPostScanMenu(const std::string& path, ScanRun run) {
    std::string currentVerdict = run.verdict.label;
    bool credentialRisk = hasCredentialExposure(run.report.findings);
    if (currentVerdict == "BLOCK" || credentialRisk) printCredentialRecoveryChecklist();

    for (;;) {
        std::cout << "\nPOST-SCAN ACTIONS\n"
                     "=================\n"
                  << "Project result: " << currentVerdict << "\n"
                     "  1. Clean confirmed malicious files\n"
                     "  2. Verify by scanning this project again\n"
                     "  3. Protect this project and its Git workflow\n"
                     "  4. Show credential recovery steps\n"
                     "  0. Return to the main menu\n"
                     "Choose an option: ";
        std::string choice;
        if (!std::getline(std::cin, choice)) return;
        choice = trim(choice);

        if (choice == "0") return;
        if (choice == "1") {
            if (currentVerdict != "BLOCK") {
                std::cout << "Automatic cleaning is available only for BLOCK results with confirmed eligible files.\n";
                continue;
            }
            cmdRemediate(path, "", false, false);
            std::cout << "\nType YES to quarantine only the confirmed actions above, or press Enter to cancel: ";
            std::string confirmation;
            std::getline(std::cin, confirmation);
            if (confirmation != "YES") {
                std::cout << "No files were changed.\n";
                continue;
            }
            cmdRemediate(path, "", true, false);
            // Re-scan directly for the current verdict rather than
            // inferring it from cmdRemediate's exit code: an exit code
            // alone can't distinguish "still BLOCK, nothing was eligible to
            // quarantine" from "genuinely unresolved after a real change",
            // and collapsing that distinction is exactly what previously
            // left this menu showing UNRESOLVED while a plain scan of the
            // same path still correctly reported BLOCK.
            run = runScan(path, "");
            currentVerdict = run.verdict.label;
            credentialRisk = hasCredentialExposure(run.report.findings);
            printCredentialRecoveryChecklist();
        } else if (choice == "2") {
            run = runScan(path, "");
            reportTo(path, fs::absolute(path).string(), run.report.findings,
                    run.report.coverage, run.trust, run.verdict);
            currentVerdict = run.verdict.label;
            credentialRisk = hasCredentialExposure(run.report.findings);
            if (currentVerdict == "BLOCK" || credentialRisk) printCredentialRecoveryChecklist();
        } else if (choice == "3") {
            if (cmdProtect(path) == 0)
                std::cout << "Git commit/push guards and continuous project protection are active.\n";
        } else if (choice == "4") {
            printCredentialRecoveryChecklist();
        } else {
            std::cout << "Invalid option. Enter a number from 0 to 4.\n";
        }
    }
}

void runInteractiveScanOne(const std::string& path) {
    if (!fs::exists(path)) {
        std::cerr << "That path does not exist: " << sanitizeForOutput(path) << "\n";
        return;
    }
    auto run = runScan(path, "");
    reportTo(path, fs::absolute(path).string(), run.report.findings,
            run.report.coverage, run.trust, run.verdict);
    runPostScanMenu(path, std::move(run));
}

int runInteractiveMenu() {
    for (;;) {
        std::cout << "\n============================================================\n"
                     " ABYSS " << kAbyssVersion << " — DEVELOPER PROTECTION AND MALWARE RESPONSE\n"
                     "============================================================\n"
                     " START HERE\n"
                     "\n"
                     "  [1] SCAN ONE PROJECT\n"
                     "      Example path: C:\\dev\\my-project\n"
                     "\n"
                     "  [2] SCAN MANY PROJECTS\n"
                     "      Example parent folder: C:\\dev\n"
                     "\n"
                     " Copy the path from File Explorer and paste it directly.\n"
                     " Quotes are not required.\n"
                     "------------------------------------------------------------\n"
                     " SAFE GITHUB WORKFLOW\n"
                     "  3. Safe clone — scan before the repository becomes active\n"
                     "  4. Safe pull — scan incoming changes before merging\n"
                     "------------------------------------------------------------\n"
                     " RECOVERY AND PROTECTION\n"
                     "  5. Clean one infected project\n"
                     "  6. Verify a project after cleaning\n"
                     "  7. Protect a clean project and its Git workflow\n"
                     "  8. Show credential recovery steps\n"
                     "  9. View or restore quarantine\n"
                     " 10. Scan this whole PC (repositories, VS Code, persistence locations)\n"
                     " 11. Show protection status\n"
                     "  0. Exit\n"
                     "------------------------------------------------------------\n"
                     "Choose an option: ";
        std::string choice;
        if (!std::getline(std::cin, choice)) return 0;
        choice = trim(choice);

        if (choice == "0") return 0;
        if (choice == "1") {
            std::string path = askPath("Paste the full path of the project to scan");
            if (!path.empty()) runInteractiveScanOne(path);
        } else if (choice == "2") {
            std::string parent = askPath("Paste the parent folder containing all projects");
            if (!parent.empty()) {
                int result = cmdScanAll(parent, "", false);
                if (result == static_cast<int>(evidence::ExitCode::Blocked)) {
                    std::cout << "\nType YES to quarantine confirmed evidence in every BLOCKED project "
                                 "listed above, or press Enter to review them individually: ";
                    std::string confirmation;
                    std::getline(std::cin, confirmation);
                    if (confirmation == "YES") cmdScanAll(parent, "", true);
                    else std::cout << "No files were changed.\n";
                }
            }
            pauseMenu();
        } else if (choice == "3") {
            std::string remote = askPath("Paste the HTTPS or SSH GitHub repository URL");
            std::string destination = askPath("Paste the new destination folder path");
            if (!remote.empty() && !destination.empty() && cmdClone(remote, destination, "") == 0) {
                std::cout << "The repository passed scanning and is now active at "
                          << sanitizeForOutput(destination) << ".\n";
            }
            pauseMenu();
        } else if (choice == "4") {
            std::string path = askPath("Paste the existing local repository path");
            if (!path.empty()) cmdPull(path, "");
            pauseMenu();
        } else if (choice == "5") {
            std::string path = askPath("Infected project path");
            if (!path.empty()) {
                cmdRemediate(path, "", false, false);
                std::cout << "\nType YES to apply only the Critical and Confirmed actions shown above: ";
                std::string confirmation;
                std::getline(std::cin, confirmation);
                if (confirmation == "YES") cmdRemediate(path, "", true, false);
                else std::cout << "No files were changed.\n";
            }
            pauseMenu();
        } else if (choice == "6") {
            std::string path = askPath("Project path to verify");
            if (!path.empty()) cmdRemediate(path, "", false, true);
            pauseMenu();
        } else if (choice == "7") {
            std::string path = askPath("Project path to protect");
            if (!path.empty()) cmdProtect(path);
            pauseMenu();
        } else if (choice == "8") {
            printCredentialRecoveryChecklist();
            pauseMenu();
        } else if (choice == "9") {
            cmdQuarantineList();
            std::cout << "\nEnter a record ID to restore it, or press Enter to return: ";
            std::string id;
            std::getline(std::cin, id);
            id = trim(id);
            if (!id.empty()) cmdQuarantineRestore(id, false);
            pauseMenu();
        } else if (choice == "10") {
            cmdSystemScan(false, "");
            printCredentialRecoveryChecklist();
            pauseMenu();
        } else if (choice == "11") {
            cmdStatus();
            pauseMenu();
        } else {
            std::cout << "Invalid option. Enter a number from 0 to 11.\n";
        }
    }
}

} // namespace

int main(int argc, char** argv) {
#if defined(_WIN32)
    // Source is compiled /utf-8, so string literals (including the em
    // dashes used throughout finding descriptions and the interactive
    // menu) are UTF-8 bytes. Windows consoles default to the legacy OEM
    // code page (often CP437) for interpreting output, which garbles any
    // non-ASCII byte sequence into mojibake like "ΓÇö" instead of "—".
    // Setting both codepages to UTF-8 up front fixes this for the whole
    // process, in both cmd.exe and PowerShell.
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) {
        return runInteractiveMenu();
    }

    std::string command = args[0];
    if (command == "version" || command == "--version" || command == "-V") {
        std::cout << "Abyss " << kAbyssVersion << "\n";
        return 0;
    }
    bool jsonOutput = false;
    bool confirmed = false;
    bool force = false;
    std::string rulesOverride;
    std::vector<std::string> positional;

    for (std::size_t i = 1; i < args.size(); i++) {
        if (args[i] == "--json") jsonOutput = true;
        else if (args[i] == "--yes") confirmed = true;
        else if (args[i] == "--force") force = true;
        else if (args[i] == "--rules" && i + 1 < args.size()) rulesOverride = args[++i];
        else positional.push_back(args[i]);
    }

    if (command == "check") return cmdCheck();

    if (command == "scan") {
        if (positional.empty()) { std::cerr << "abyss scan: missing <path>\n"; return 2; }
        return cmdScan(positional[0], jsonOutput, rulesOverride);
    }
    if (command == "scan-all") {
        if (positional.empty()) { std::cerr << "abyss scan-all: missing <parent>\n"; return 2; }
        return cmdScanAll(positional[0], rulesOverride, confirmed);
    }
    if (command == "system-scan") return cmdSystemScan(jsonOutput, rulesOverride);
    if (command == "preflight") {
        if (positional.empty()) { std::cerr << "abyss preflight: missing <path>\n"; return 2; }
        return cmdPreflight(positional[0], rulesOverride);
    }
    if (command == "open") {
        if (positional.empty()) { std::cerr << "abyss open: missing <path>\n"; return 2; }
        return cmdOpen(positional[0], rulesOverride);
    }
    if (command == "contain" || command == "remediate") {
        if (positional.empty()) { std::cerr << "abyss " << command << ": missing <path>\n"; return 2; }
        return cmdRemediate(positional[0], rulesOverride, confirmed, false);
    }
    if (command == "verify") {
        if (positional.empty()) { std::cerr << "abyss verify: missing <path>\n"; return 2; }
        return cmdRemediate(positional[0], rulesOverride, false, true);
    }
    if (command == "quarantine" && positional.size() == 1 && positional[0] == "list") return cmdQuarantineList();
    if (command == "quarantine" && positional.size() >= 2 && positional[0] == "restore")
        return cmdQuarantineRestore(positional[1], force);
    if (command == "rules" && args.size() >= 2 && args[1] == "list") return cmdRulesList(rulesOverride);
    if (command == "rules" && args.size() >= 2 && args[1] == "verify") return cmdRulesVerify(rulesOverride);
    if (command == "self-scan") return cmdSelfScan();
    if (command == "status") return cmdStatus();
    if (command == "clone") {
        if (positional.size() < 2) { std::cerr << "abyss clone: expected <url> <path>\n"; return 2; }
        return cmdClone(positional[0], positional[1], rulesOverride);
    }
    if (command == "pull") {
        if (positional.empty()) { std::cerr << "abyss pull: missing <path>\n"; return 2; }
        return cmdPull(positional[0], rulesOverride);
    }
    if (command == "protect") {
        if (positional.empty()) { std::cerr << "abyss protect: missing <path>\n"; return 2; }
        return cmdProtect(positional[0]);
    }
    if (command == "unprotect") {
        if (positional.empty()) { std::cerr << "abyss unprotect: missing <path>\n"; return 2; }
        return cmdUnprotect(positional[0]);
    }
    if (command == "timeline") {
        if (positional.empty()) { std::cerr << "abyss timeline: missing <path>\n"; return 2; }
        return cmdTimeline(positional[0], false);
    }
    if (command == "graph") {
        if (positional.empty()) { std::cerr << "abyss graph: missing <path>\n"; return 2; }
        return cmdTimeline(positional[0], true);
    }
    if (command == "recover") {
        if (positional.size() < 3) { std::cerr << "abyss recover: expected <repo> <commit> <destination>\n"; return 2; }
        return cmdRecover(positional[0], positional[1], positional[2], rulesOverride);
    }
    if (command == "service") return runAsService();

    if (command == "--help" || command == "-h" || command == "help") {
        printUsage();
        return 0;
    }

    std::cerr << "abyss: unknown command '" << command << "'\n\n";
    printUsage();
    return 2;
}
