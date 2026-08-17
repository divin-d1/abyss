#include "rules/rules.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <unordered_map>

#include "crypto/sha256.h"
#include "rules/trust_anchor.h"

namespace abyss::rules {

namespace fs = std::filesystem;

namespace {

std::string lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return r;
}

std::string upper(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return (char)std::toupper(c); });
    return r;
}

bool contains(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return false;
    return haystack.find(needle) != std::string::npos;
}

bool isValidSha256Hex(const std::string& s) {
    if (s.size() != 64) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

Rule parseRuleBlock(const Block& b, const std::string& sourceFile, std::vector<std::string>& errors) {
    Rule r;
    r.sourceFile = sourceFile;
    r.id = b.get("id");
    r.name = b.get("name", r.id);
    r.description = b.get("description");
    r.campaign = b.get("campaign");

    if (r.id.empty()) {
        errors.push_back(sourceFile + ": rule missing 'id'");
        r.sourceFileValid = false;
    }

    auto versionOpt = parseStrictInt(b.get("version", "1"));
    if (!versionOpt || *versionOpt < 1 || *versionOpt > 1000000) {
        errors.push_back(sourceFile + ": rule '" + r.id + "' has invalid/poisoned version (" +
                          b.get("version", "1") + ") — must be a positive integer");
        r.sourceFileValid = false;
        r.version = 1;
    } else {
        r.version = (int)*versionOpt;
    }

    auto typeOpt = ruleTypeFromString(b.get("type", "IOC"));
    if (!typeOpt) {
        errors.push_back(sourceFile + ": rule '" + r.id + "' has invalid type");
        r.sourceFileValid = false;
    } else {
        r.type = *typeOpt;
    }

    auto sevOpt = severityFromString(b.get("severity", "MEDIUM"));
    if (!sevOpt) {
        errors.push_back(sourceFile + ": rule '" + r.id + "' has invalid severity");
        r.sourceFileValid = false;
    } else {
        r.severity = *sevOpt;
    }

    auto confOpt = confidenceFromString(b.get("confidence", "MEDIUM"));
    if (!confOpt) {
        errors.push_back(sourceFile + ": rule '" + r.id + "' has invalid confidence");
        r.sourceFileValid = false;
    } else {
        r.confidence = *confOpt;
    }

    if (b.has("tags")) r.tags = Block::splitList(b.get("tags"));
    if (b.has("applies_to")) r.appliesToExtensions = Block::splitList(b.get("applies_to"));

    for (const auto& v : b.getAll("match.contains_all")) r.containsAll.push_back(v);
    for (const auto& v : b.getAll("match.contains")) r.containsAll.push_back(v);
    for (const auto& v : b.getAll("match.contains_any")) {
        auto list = Block::splitList(v);
        r.containsAny.insert(r.containsAny.end(), list.begin(), list.end());
    }
    for (const auto& v : b.getAll("match.contains_none")) {
        auto list = Block::splitList(v);
        r.containsNone.insert(r.containsNone.end(), list.begin(), list.end());
    }
    for (const auto& v : b.getAll("match.filename")) r.filenameEquals.push_back(lower(v));
    for (const auto& v : b.getAll("match.filename_contains")) r.filenameContains.push_back(lower(v));
    for (const auto& v : b.getAll("match.sha256")) {
        for (auto& h : Block::splitList(v)) {
            std::string hl = lower(h);
            if (!isValidSha256Hex(hl)) {
                errors.push_back(sourceFile + ": rule '" + r.id + "' has an invalid/poisoned match.sha256 value ('" +
                                  h + "' is not 64 hex characters)");
                r.sourceFileValid = false;
                continue;
            }
            r.sha256Hashes.push_back(hl);
        }
    }

    // `require_all_groups=true` is kept as a legacy alias for `logic=ALL`
    // (rules authored before the ALL/ANY/N_OF combinator existed).
    std::string logicStr = upper(b.get("logic", ""));
    if (logicStr.empty()) {
        r.logic = (lower(b.get("require_all_groups", "false")) == "true") ? RuleLogic::All : RuleLogic::Any;
    } else if (logicStr == "ALL") {
        r.logic = RuleLogic::All;
    } else if (logicStr == "ANY") {
        r.logic = RuleLogic::Any;
    } else if (logicStr == "N_OF" || logicStr == "NOF") {
        r.logic = RuleLogic::NOf;
    } else {
        errors.push_back(sourceFile + ": rule '" + r.id + "' has invalid logic '" + logicStr +
                          "' (expected ALL, ANY, or N_OF)");
        r.sourceFileValid = false;
    }

    auto nOfOpt = parseStrictInt(b.get("n_of_threshold", "1"));
    r.nOfThreshold = (nOfOpt && *nOfOpt >= 1 && *nOfOpt <= 1000) ? (int)*nOfOpt : 1;
    if (r.logic == RuleLogic::NOf && (!nOfOpt || *nOfOpt < 1 || *nOfOpt > 1000)) {
        errors.push_back(sourceFile + ": rule '" + r.id + "' has invalid/poisoned n_of_threshold (" +
                          b.get("n_of_threshold", "1") + ") — must be a positive integer");
        r.sourceFileValid = false;
    }

    int groupCount = (r.filenameEquals.empty() ? 0 : 1) + (r.filenameContains.empty() ? 0 : 1) +
                      (r.containsAll.empty() ? 0 : 1) + (r.containsAny.empty() ? 0 : 1) +
                      (r.containsNone.empty() ? 0 : 1) + (r.sha256Hashes.empty() ? 0 : 1);
    if (r.logic == RuleLogic::NOf && r.nOfThreshold > groupCount && groupCount > 0) {
        errors.push_back(sourceFile + ": rule '" + r.id + "' has contradictory n_of_threshold=" +
                          std::to_string(r.nOfThreshold) + " but only " + std::to_string(groupCount) +
                          " condition group(s) configured — this rule could never match");
        r.sourceFileValid = false;
    }

    if (groupCount == 0 && r.type != RuleType::Behavior && r.type != RuleType::Correlation) {
        errors.push_back(sourceFile + ": rule '" + r.id + "' has no evaluable match.* condition");
    }

    return r;
}

} // namespace

RuleLoadResult loadRulesFromFile(const std::string& path) {
    RuleLoadResult result;
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        result.errors.push_back(path + ": could not open");
        return result;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    auto parsed = parseBlocks(ss.str());
    if (!parsed.ok) {
        result.errors.push_back(path + ": " + parsed.error);
        return result;
    }
    for (const auto& block : parsed.blocks) {
        if (block.section != "rule") continue;
        auto rule = parseRuleBlock(block, path, result.errors);
        if (rule.sourceFileValid) result.rules.push_back(std::move(rule));
    }
    return result;
}

RuleLoadResult loadRulesFromDirectory(const std::string& dir) {
    RuleLoadResult result;
    std::error_code ec;
    if (!fs::exists(dir, ec)) return result;
    for (auto it = fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;
        if (!it->is_regular_file(ec)) continue;
        if (it->path().extension() != ".rules") continue;
        auto sub = loadRulesFromFile(pathToUtf8(it->path()));
        result.rules.insert(result.rules.end(), sub.rules.begin(), sub.rules.end());
        result.errors.insert(result.errors.end(), sub.errors.begin(), sub.errors.end());
    }
    return result;
}

namespace {

// One condition group's evaluation result: whether it matched, and the
// evidence text to surface if it did. `present` distinguishes "this group
// has no conditions configured" (ignored entirely) from "configured but
// didn't match" (counts as a failure under require_all_groups).
struct GroupResult {
    bool present = false;
    bool matched = false;
    std::string evidence;
};

GroupResult evalFilenameEquals(const rules::Rule& r, const std::string& lowerFilename,
                                const std::string& filename) {
    GroupResult g;
    if (r.filenameEquals.empty()) return g;
    g.present = true;
    for (const auto& fn : r.filenameEquals) {
        if (lowerFilename == fn) { g.matched = true; g.evidence = filename; return g; }
    }
    return g;
}

GroupResult evalFilenameContains(const rules::Rule& r, const std::string& lowerFilename,
                                  const std::string& filename) {
    GroupResult g;
    if (r.filenameContains.empty()) return g;
    g.present = true;
    for (const auto& fn : r.filenameContains) {
        if (contains(lowerFilename, fn)) { g.matched = true; g.evidence = filename; return g; }
    }
    return g;
}

GroupResult evalContainsAll(const rules::Rule& r, const std::string& content) {
    GroupResult g;
    if (r.containsAll.empty()) return g;
    g.present = true;
    for (const auto& needle : r.containsAll) {
        if (!contains(content, needle)) return g; // matched stays false
    }
    g.matched = true;
    g.evidence = r.containsAll.front();
    return g;
}

GroupResult evalContainsAny(const rules::Rule& r, const std::string& content) {
    GroupResult g;
    if (r.containsAny.empty()) return g;
    g.present = true;
    for (const auto& needle : r.containsAny) {
        if (contains(content, needle)) { g.matched = true; g.evidence = needle; return g; }
    }
    return g;
}

// Negation: the group "matches" (the rule's condition is satisfied) only if
// NONE of the forbidden substrings are present.
GroupResult evalContainsNone(const rules::Rule& r, const std::string& content) {
    GroupResult g;
    if (r.containsNone.empty()) return g;
    g.present = true;
    for (const auto& needle : r.containsNone) {
        if (contains(content, needle)) { g.evidence = "NOT " + needle; return g; } // matched stays false
    }
    g.matched = true;
    return g;
}

GroupResult evalSha256(const rules::Rule& r, const std::string& sha256Lower) {
    GroupResult g;
    if (r.sha256Hashes.empty()) return g;
    g.present = true;
    if (sha256Lower.empty()) return g; // hashing wasn't performed — cannot match, not an error
    for (const auto& h : r.sha256Hashes) {
        if (h == sha256Lower) { g.matched = true; g.evidence = "sha256:" + h; return g; }
    }
    return g;
}

} // namespace

std::vector<Finding> RuleEngine::evaluateFile(const std::string& relPath, const std::string& filename,
                                               const std::string& extensionLower, const std::string& content,
                                               const std::string& sha256Lower) const {
    std::vector<Finding> findings;
    std::string lowerFilename = lower(filename);

    for (const auto& r : rules_) {
        if (!r.appliesToExtensions.empty()) {
            bool extMatch = false;
            for (const auto& e : r.appliesToExtensions) {
                if (lower(e) == extensionLower) { extMatch = true; break; }
            }
            if (!extMatch) continue;
        }

        std::array<GroupResult, 6> groups = {
            evalFilenameEquals(r, lowerFilename, filename),
            evalFilenameContains(r, lowerFilename, filename),
            evalContainsAll(r, content),
            evalContainsAny(r, content),
            evalContainsNone(r, content),
            evalSha256(r, sha256Lower),
        };

        std::vector<const GroupResult*> present;
        for (const auto& g : groups) {
            if (g.present) present.push_back(&g);
        }

        bool matched = false;
        std::string evidence;
        if (!present.empty()) {
            switch (r.logic) {
                case RuleLogic::All: {
                    matched = true;
                    for (const auto* g : present) {
                        if (!g->matched) { matched = false; break; }
                        if (!g->evidence.empty()) evidence += (evidence.empty() ? "" : " + ") + g->evidence;
                    }
                    break;
                }
                case RuleLogic::NOf: {
                    int count = 0;
                    std::vector<std::string> evs;
                    for (const auto* g : present) {
                        if (g->matched) {
                            count++;
                            if (!g->evidence.empty()) evs.push_back(g->evidence);
                        }
                    }
                    matched = count >= r.nOfThreshold;
                    if (matched) {
                        for (std::size_t i = 0; i < evs.size(); i++) evidence += (i ? " + " : "") + evs[i];
                    }
                    break;
                }
                case RuleLogic::Any:
                default: {
                    for (const auto* g : present) {
                        if (g->matched) { matched = true; evidence = g->evidence; break; }
                    }
                    break;
                }
            }
        }

        if (!matched) continue;

        Finding f;
        f.findingId = nextFindingId();
        f.ruleId = r.id;
        f.ruleName = r.name;
        f.type = r.type;
        f.severity = r.severity;
        f.confidence = r.confidence;
        f.description = r.description;
        f.filePath = relPath;
        f.evidence = evidence.size() > 120 ? evidence.substr(0, 120) + "..." : evidence;
        f.tags = r.tags;
        f.campaign = r.campaign;
        f.attributionConfidence = r.campaign.empty() ? Confidence::Unknown : Confidence::Medium;
        findings.push_back(std::move(f));
    }
    return findings;
}

namespace {

// Rejects a manifest-listed relative path unless it canonicalizes to a
// location *inside* rulesDir: no absolute path, no `..` component, and no
// symlink/junction anywhere on the resolved path that would let it point
// somewhere else entirely. Returns the canonical absolute path on success.
std::optional<fs::path> resolveManifestPathSafely(const fs::path& rulesDirCanonical, const std::string& relPath,
                                                   std::string& rejectReason) {
    fs::path rel(relPath);
    if (rel.is_absolute()) {
        rejectReason = "absolute path not allowed in manifest";
        return std::nullopt;
    }
    for (const auto& part : rel) {
        if (part == "..") {
            rejectReason = "'..' path traversal not allowed in manifest";
            return std::nullopt;
        }
    }

    std::error_code ec;
    fs::path candidate = rulesDirCanonical / rel;
    fs::path resolved = fs::weakly_canonical(candidate, ec);
    if (ec || !pathStartsWith(resolved, rulesDirCanonical)) {
        rejectReason = "resolves outside the rules directory (possible symlink/junction escape)";
        return std::nullopt;
    }

    // Reject if any ancestor directory component between rulesDir and the
    // target is itself a reparse point — weakly_canonical resolves the
    // *final* target but a symlinked intermediate directory could still be
    // used to smuggle the read through a location outside admin control.
    fs::path probe = rulesDirCanonical;
    for (const auto& part : rel) {
        probe /= part;
        if (isReparsePoint(probe)) {
            rejectReason = "path traverses a symlink/junction/reparse point";
            return std::nullopt;
        }
    }

    return resolved;
}

} // namespace

ManifestVerification verifyRuleManifest(const std::string& rulesDir) {
    ManifestVerification result;
    std::error_code ec;
    fs::path rulesDirCanonical = fs::weakly_canonical(rulesDir, ec);
    if (ec) rulesDirCanonical = fs::absolute(rulesDir);

    fs::path manifestPath = rulesDirCanonical / "MANIFEST.sha256";
    if (!fs::exists(manifestPath, ec)) return result; // manifestFound stays false -> caller treats as degraded
    result.manifestFound = true;

    std::vector<std::uint8_t> manifestBytes;
    bool truncated = false;
    if (!readFileBytes(pathToUtf8(manifestPath), manifestBytes, truncated, 8ull * 1024 * 1024)) {
        result.errors.push_back(pathToUtf8(manifestPath) + ": could not read manifest file");
        return result;
    }
    result.manifestReadable = true;
    std::string manifestText = bytesToStringLossy(manifestBytes);

    result.anchorAvailable = kOfficialManifestSha256[0] != '\0';
    if (result.anchorAvailable) {
        std::string actualManifestHash =
            lower(crypto::sha256Hex(reinterpret_cast<const std::uint8_t*>(manifestText.data()), manifestText.size()));
        result.anchorVerified = actualManifestHash == lower(kOfficialManifestSha256);
        if (!result.anchorVerified) {
            result.mismatches.push_back(
                "MANIFEST.sha256: does not match the trust anchor compiled into this binary — the manifest "
                "itself has been replaced or modified since this build was compiled");
        }
    }

    std::set<std::string> listedRelPaths;
    for (const auto& rawLine : splitLines(manifestText)) {
        std::string t = trim(rawLine);
        if (t.empty() || t[0] == '#') continue;
        std::size_t sep = t.find("  ");
        if (sep == std::string::npos) sep = t.find(' ');
        if (sep == std::string::npos) {
            result.mismatches.push_back(t + ": malformed manifest line");
            continue;
        }
        std::string expectedHash = lower(trim(t.substr(0, sep)));
        std::string relPath = trim(t.substr(sep));
        if (!isValidSha256Hex(expectedHash)) {
            result.mismatches.push_back(relPath + ": manifest entry has an invalid hash format");
            continue;
        }

        if (!listedRelPaths.insert(relPath).second) {
            result.rejectedPaths.push_back(relPath + ": duplicate entry in manifest");
            continue;
        }

        std::string rejectReason;
        auto safePath = resolveManifestPathSafely(rulesDirCanonical, relPath, rejectReason);
        if (!safePath) {
            result.rejectedPaths.push_back(relPath + ": " + rejectReason);
            continue;
        }

        std::vector<std::uint8_t> fileBytes;
        bool fileTruncated = false;
        if (!readFileBytes(safePath->string(), fileBytes, fileTruncated, 64ull * 1024 * 1024)) {
            result.mismatches.push_back(relPath + ": listed in manifest but missing or unreadable on disk");
            continue;
        }
        std::string actualHash = lower(crypto::sha256Hex(fileBytes));
        if (actualHash != expectedHash) {
            result.mismatches.push_back(relPath + ": hash mismatch (file was modified after the manifest was generated)");
        }
    }

    // Any .rules/.esr file present on disk but not listed in the manifest
    // is untracked — an attacker who could write into the rules directory
    // could otherwise add a brand-new malicious rule file that a
    // per-listed-file hash check alone would never catch. Symlinked
    // directories are not followed during this walk (consistent with
    // scanner::discoverRepository's containment policy).
    fs::recursive_directory_iterator it(rulesDirCanonical, fs::directory_options::skip_permission_denied, ec);
    fs::recursive_directory_iterator endIt;
    if (ec) {
        result.errors.push_back(pathToUtf8(rulesDirCanonical) + ": " + ec.message());
    } else {
        while (it != endIt) {
            std::error_code symEc;
            bool isSym = (!symEc && fs::is_symlink(it->symlink_status(symEc))) || isReparsePoint(it->path());
            if (isSym) {
                it.disable_recursion_pending();
                std::error_code incEc;
                it.increment(incEc);
                if (incEc) { result.errors.push_back(pathToUtf8(it->path()) + ": " + incEc.message()); break; }
                continue;
            }

            std::error_code typeEc;
            bool isRegular = it->is_regular_file(typeEc);
            if (typeEc) {
                result.errors.push_back(pathToUtf8(it->path()) + ": " + typeEc.message());
                std::error_code incEc;
                it.increment(incEc);
                if (incEc) break;
                continue;
            }
            if (isRegular) {
                auto ext = it->path().extension();
                if (ext == ".rules" || ext == ".esr") {
                    std::error_code relEc;
                    std::string rel = pathToUtf8(fs::relative(it->path(), rulesDirCanonical, relEc));
                    std::replace(rel.begin(), rel.end(), '\\', '/');
                    if (!listedRelPaths.count(rel)) result.untracked.push_back(rel);
                }
            }
            std::error_code incEc;
            it.increment(incEc);
            if (incEc) { result.errors.push_back(pathToUtf8(it->path()) + ": " + incEc.message()); break; }
        }
    }

    result.allVerified = result.mismatches.empty() && result.untracked.empty() && result.rejectedPaths.empty() &&
                          result.errors.empty() && (!result.anchorAvailable || result.anchorVerified);
    return result;
}

std::vector<std::string> findDuplicateRuleIds(const std::vector<Rule>& rules) {
    std::vector<std::string> errors;
    std::unordered_map<std::string, std::vector<std::string>> byId; // id -> source files
    for (const auto& r : rules) {
        if (!r.id.empty()) byId[r.id].push_back(r.sourceFile);
    }
    for (const auto& [id, sources] : byId) {
        if (sources.size() <= 1) continue;
        std::string joined;
        for (std::size_t i = 0; i < sources.size(); i++) joined += (i ? ", " : "") + sources[i];
        errors.push_back("duplicate rule id '" + id + "' defined in: " + joined);
    }
    return errors;
}

} // namespace abyss::rules
