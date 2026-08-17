#pragma once

#include <ostream>
#include <string>
#include <vector>

#include "core/core.h"
#include "scanner/scanner.h"

namespace abyss::evidence {

// The exit-code contract (see README.md "Trusted rule boundary and
// fail-closed behavior"), used consistently across every Abyss command that
// evaluates evidence. Verdict::label uses the plain outcome words below;
// ExitCode is the stable numeric contract scripts can depend on:
//   0 Clean / "ALLOW"        no compromise detected, complete coverage, AND
//                            official (not local-override) verified rule trust
//   1 Blocked / "BLOCK"      a Critical finding was confirmed / a security violation
//   2 OperationalFailure /   the run itself couldn't be trusted (degraded/missing/
//     "INCOMPLETE"           tampered rules) or coverage was incomplete — never Clean
//   3 SuspiciousReview /     High/Medium findings present, or non-official rules were
//     "REVIEW"               used — manual review recommended, not an ALLOW
//   4 Unresolved /            a requested containment/recovery action (remediate,
//     "UNRESOLVED"            clone, pull, protect, ...) did not reach a verified
//                             state — distinct from a plain scan REVIEW/BLOCK
// High or Critical findings must never silently produce exit code 0, and
// REVIEW must never be presented as an unconditional ALLOW.
enum class ExitCode {
    Clean = 0,
    Blocked = 1,
    OperationalFailure = 2,
    SuspiciousReview = 3,
    Unresolved = 4
};

std::string toString(ExitCode c);

// Describes where the rule pack actually came from and whether it can be
// trusted for this run. Built by the CLI's rule-loading step (see
// README.md "Trusted rule boundary") and threaded through to the
// verdict — a scan can never report a clean result on unverified/corrupt/
// missing official rules.
struct RuleTrustStatus {
    std::string trustLevel;      // "official" | "local-override" | "none"
    std::string integrityStatus; // "verified" | "unverified-no-manifest" | "tampered" | "no-rules-found" | "parse-errors"
    bool degraded = false;       // true => clearance unavailable regardless of findings
    std::string details;
};

struct Verdict {
    ExitCode exitCode = ExitCode::Clean;
    std::string label;       // short machine-checkable label, e.g. "BLOCKED"
    std::string explanation;
};

// Computes the run's final verdict from coverage + findings + rule trust.
// Priority: degraded rules > Critical finding > incomplete coverage >
// High/Medium finding > clean. See README.md forensic-honesty
// rule — this function is the single place that decision is made, so every
// command (scan/preflight/self-scan) reports it identically.
Verdict computeVerdict(const scanner::ScanCoverage& coverage, const std::vector<Finding>& findings,
                        const RuleTrustStatus& trust);

// Writes one JSON object per line (JSONL), sorted by severity descending
// then file path, so the most important findings surface first without
// requiring a JSON library on the consuming end. All string fields are
// passed through sanitizeForOutput before escaping (defense in depth —
// jsonEscape already neutralizes control bytes for JSON's own syntax, but
// this keeps both output paths consistent).
void writeFindingsJsonl(const std::vector<Finding>& findings, std::ostream& out);

// Writes the human-readable console report, including rule-trust status and
// the final verdict. Never prints an unconditional "clean" verdict — see
// README.md. Every untrusted string (file paths, evidence
// excerpts, descriptions, tags, campaign names) is passed through
// sanitizeForOutput first, so a malicious filename/evidence excerpt can't
// inject terminal escape sequences into the report.
void writeHumanReport(const std::string& scopeLabel, const std::vector<Finding>& findings,
                       const scanner::ScanCoverage& coverage, const RuleTrustStatus& trust,
                       const Verdict& verdict, std::ostream& out);

// Highest severity present across a finding set; Severity::Info if empty.
Severity maxSeverity(const std::vector<Finding>& findings);

std::vector<Finding> sortedBySeverityDesc(std::vector<Finding> findings);

} // namespace abyss::evidence
