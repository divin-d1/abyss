#include "evidence/evidence.h"

#include <algorithm>
#include <iomanip>

namespace abyss::evidence {

namespace {
int severityRank(Severity s) {
    switch (s) {
        case Severity::Critical: return 4;
        case Severity::High: return 3;
        case Severity::Medium: return 2;
        case Severity::Low: return 1;
        case Severity::Info: return 0;
    }
    return 0;
}

// A finding with every untrusted string field sanitized for safe display —
// built just before printing so internal logic (sorting, verdict math)
// always sees the original data. Two independent passes: redactSecrets()
// targets *meaning* (credential-shaped values are replaced but surrounding
// context is kept so the finding stays investigable), sanitizeForOutput()
// targets terminal/control-byte safety. Order matters: redact first, since
// a secret's own bytes could otherwise be mistaken for control sequences.
Finding sanitizedCopy(const Finding& f) {
    Finding s = f;
    s.filePath = sanitizeForOutput(s.filePath);
    s.description = sanitizeForOutput(redactSecrets(s.description));
    s.evidence = sanitizeForOutput(redactSecrets(s.evidence), 200);
    s.campaign = sanitizeForOutput(s.campaign);
    s.ruleName = sanitizeForOutput(s.ruleName);
    for (auto& t : s.tags) t = sanitizeForOutput(t, 80);
    return s;
}
} // namespace

std::string toString(ExitCode c) {
    switch (c) {
        case ExitCode::Clean: return "CLEAN";
        case ExitCode::Blocked: return "BLOCKED";
        case ExitCode::OperationalFailure: return "OPERATIONAL_FAILURE";
        case ExitCode::SuspiciousReview: return "SUSPICIOUS_REVIEW";
        case ExitCode::Unresolved: return "UNRESOLVED";
    }
    return "UNKNOWN";
}

Severity maxSeverity(const std::vector<Finding>& findings) {
    Severity best = Severity::Info;
    for (const auto& f : findings) {
        if (severityRank(f.severity) > severityRank(best)) best = f.severity;
    }
    return best;
}

std::vector<Finding> sortedBySeverityDesc(std::vector<Finding> findings) {
    std::stable_sort(findings.begin(), findings.end(), [](const Finding& a, const Finding& b) {
        if (severityRank(a.severity) != severityRank(b.severity)) return severityRank(a.severity) > severityRank(b.severity);
        return a.filePath < b.filePath;
    });
    return findings;
}

namespace {
// Confidence levels present among findings at a given severity — used so
// the verdict's language never overstates certainty. "Confirmed" language
// is reserved for Confirmed/High confidence; Low/Medium confidence
// Critical findings are described as needing urgent review, not as an
// established fact.
bool anyAtSeverityWithConfidenceAtLeast(const std::vector<Finding>& findings, Severity sev, Confidence minConf) {
    auto rank = [](Confidence c) {
        switch (c) {
            case Confidence::Confirmed: return 4;
            case Confidence::High: return 3;
            case Confidence::Medium: return 2;
            case Confidence::Low: return 1;
            case Confidence::Unknown: return 0;
        }
        return 0;
    };
    for (const auto& f : findings) {
        if (f.severity == sev && rank(f.confidence) >= rank(minConf)) return true;
    }
    return false;
}
} // namespace

Verdict computeVerdict(const scanner::ScanCoverage& coverage, const std::vector<Finding>& findings,
                        const RuleTrustStatus& trust) {
    Verdict v;

    if (trust.degraded) {
        v.exitCode = ExitCode::OperationalFailure;
        v.label = "INCOMPLETE";
        v.explanation = "Rule trust/integrity requirements were not met (" + trust.details +
                         "). Clearance is unavailable — this run cannot produce a trustworthy verdict about "
                         "compromise, regardless of what was or wasn't found.";
        return v;
    }

    Severity worst = maxSeverity(findings);

    if (worst == Severity::Critical) {
        v.exitCode = ExitCode::Blocked;
        v.label = "BLOCK";
        bool highConfidence = anyAtSeverityWithConfidenceAtLeast(findings, Severity::Critical, Confidence::High);
        v.explanation = highConfidence
            ? "One or more CRITICAL-severity findings with High/Confirmed confidence are present — treat as "
              "requiring immediate action. This still describes matched evidence, not an independently "
              "verified compromise; see each finding's own confidence and evidence excerpt."
            : "One or more CRITICAL-severity findings are present, but at Low/Medium confidence — this is "
              "not a confirmed compromise, and warrants prompt investigation rather than an automatic "
              "assumption of malicious intent.";
        return v;
    }

    if (trust.trustLevel != "official") {
        // Non-official rules (--rules/ABYSS_RULES_DIR) can still BLOCK or
        // flag for REVIEW on real findings above, but can never themselves
        // issue an official ALLOW — an explicit, unverified rule source is
        // not the trust basis an "official clearance" implies.
        v.exitCode = ExitCode::SuspiciousReview;
        v.label = "REVIEW";
        v.explanation = "No High/Critical findings, but this run used '" + trust.trustLevel +
                         "' rules (" + trust.integrityStatus +
                         "), not the official verified pack — results are not an official clearance and "
                         "should be reviewed before being treated as trustworthy.";
        return v;
    }

    if (!coverage.isComplete()) {
        v.exitCode = ExitCode::OperationalFailure;
        v.label = "INCOMPLETE";
        v.explanation = "Not all requested content could be analyzed (" +
                         std::to_string(coverage.filesUnreadable) + " unreadable, " +
                         std::to_string(coverage.filesTruncated) + " truncated, " +
                         std::to_string(coverage.symlinkEscapesSkipped) + " symlink escape(s) skipped, " +
                         std::to_string(coverage.directoryErrors) +
                         " directory error(s)) — clearance cannot be granted with incomplete coverage.";
        return v;
    }

    if (worst == Severity::High || worst == Severity::Medium) {
        v.exitCode = ExitCode::SuspiciousReview;
        v.label = "REVIEW";
        v.explanation = "Findings below CRITICAL severity are present and warrant manual review — this is "
                         "not an ALLOW.";
        return v;
    }

    v.exitCode = ExitCode::Clean;
    v.label = "ALLOW";
    v.explanation = "No compromise detected within available evidence, with complete requested coverage and "
                     "verified official rule trust.";
    return v;
}

void writeFindingsJsonl(const std::vector<Finding>& findings, std::ostream& out) {
    for (const auto& f : sortedBySeverityDesc(findings)) {
        out << findingToJsonLine(sanitizedCopy(f)) << "\n";
    }
}

void writeHumanReport(const std::string& scopeLabel, const std::vector<Finding>& findings,
                       const scanner::ScanCoverage& coverage, const RuleTrustStatus& trust,
                       const Verdict& verdict, std::ostream& out) {
    auto sorted = sortedBySeverityDesc(findings);

    out << "ABYSS SCAN REPORT\n";
    out << "=================\n";
    out << "Scope: " << sanitizeForOutput(scopeLabel) << "\n\n";

    out << "Rule trust:\n";
    out << "  Trust level:       " << trust.trustLevel << "\n";
    out << "  Integrity status:  " << trust.integrityStatus << "\n";
    if (!trust.details.empty()) out << "  Details:           " << sanitizeForOutput(trust.details) << "\n";
    out << "\n";

    out << "Telemetry coverage:\n";
    out << "  Files discovered:        " << coverage.filesDiscovered << "\n";
    out << "  Files analyzed:          " << coverage.filesAnalyzed << "\n";
    out << "  Files truncated (>cap):  " << coverage.filesTruncated << "\n";
    out << "  Files unreadable:        " << coverage.filesUnreadable << "\n";
    out << "  Symlink escapes skipped: " << coverage.symlinkEscapesSkipped << " (refused — target outside scan root)\n";
    out << "  Directory read errors:   " << coverage.directoryErrors << "\n";
    out << "  Worker threads used:     " << coverage.threadsUsed << "\n";
    out << "  Git repository detected: " << (coverage.gitDetected ? "YES" : "NO") << "\n";
    out << "  Historical process telemetry: NOT CAPTURED BY THIS SCAN\n";
    out << "  Historical network telemetry: NOT CAPTURED BY THIS SCAN\n\n";

    out << "Result: " << sorted.size() << " finding(s)";
    if (!sorted.empty()) out << " — highest severity " << toString(maxSeverity(sorted));
    out << "\n";
    out << "Verdict: " << verdict.label << " (exit code " << (int)verdict.exitCode << ")\n";
    out << sanitizeForOutput(verdict.explanation) << "\n\n";

    if (sorted.empty() && verdict.label == "ALLOW") {
        out << "This reflects the absence of matches against loaded rules and native heuristics over the\n";
        out << "files analyzed above — it is not a guarantee of a clean system. See telemetry coverage.\n";
    }

    for (const auto& raw : sorted) {
        Finding f = sanitizedCopy(raw);
        out << "[" << toString(f.severity) << "/" << toString(f.confidence) << " confidence] "
            << f.ruleName << " (" << f.ruleId << ")\n";
        out << "  File: " << f.filePath;
        if (f.line) out << ":" << *f.line;
        out << "\n";
        out << "  " << f.description << "\n";
        if (!f.evidence.empty()) out << "  Evidence: " << f.evidence << "\n";
        if (!f.campaign.empty()) {
            out << "  Campaign attribution: " << f.campaign << " (attribution confidence: "
                << toString(f.attributionConfidence) << ")\n";
        }
        if (!f.tags.empty()) {
            out << "  Tags:";
            for (const auto& t : f.tags) out << " " << t;
            out << "\n";
        }
        out << "\n";
    }
}

} // namespace abyss::evidence
