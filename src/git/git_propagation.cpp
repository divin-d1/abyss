#include "git/git_propagation.h"

#include <algorithm>
#include <set>

namespace abyss::git {

namespace {

std::string lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return r;
}

const std::set<std::string>& scriptExtensions() {
    static const std::set<std::string> exts = {".bat", ".cmd", ".ps1", ".sh"};
    return exts;
}

// ---------------------------------------------------------------------------
// Command-aware tokenizer.
//
// Real batch/shell/PowerShell scripts have structure a naive substring
// search can't tell apart: `rem git push -f` is a comment, `echo git push
// -f` prints text, `git commit -m "please --amend later"` has --amend
// inside a commit message, and `more ^` continues onto the next physical
// line. This tokenizer resolves caret line-continuations, strips
// comments (`rem`/`::`/`#`), splits on unquoted command separators
// (`&`, `&&`, `|`, `||`, `;`), and tokenizes each resulting segment with
// quote awareness — so detectors below check *command* structure, not
// raw text.
// ---------------------------------------------------------------------------

struct CommandSegment {
    std::vector<std::string> tokens; // lowercased, quotes stripped
    bool isComment = false;
    bool isEcho = false;        // first token is "echo" — its own tokens are printed text, not a command
    bool precededByPipe = false; // this segment was separated from the previous one by '|', not '&'/';'
    bool pipedFromEcho = false;  // precededByPipe AND the previous segment was an echo (resolved after parsing)
};

// Joins batch caret-continuation (`^` immediately before a line break)
// before anything else runs, matching how cmd.exe's own lexer treats it —
// continuation happens before comment/quote/separator parsing, not after.
std::string joinCaretContinuations(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); i++) {
        if (text[i] == '^' && i + 1 < text.size()) {
            std::size_t j = i + 1;
            if (text[j] == '\r') j++;
            if (j < text.size() && text[j] == '\n') {
                i = j; // skip the caret and the line break entirely
                continue;
            }
        }
        out += text[i];
    }
    return out;
}

bool isCommentLine(const std::string& trimmedLower, bool isPowershellOrShell) {
    if (trimmedLower.rfind("rem ", 0) == 0 || trimmedLower == "rem") return true;
    if (trimmedLower.rfind("::", 0) == 0) return true;
    if (isPowershellOrShell && trimmedLower.rfind("#", 0) == 0) return true;
    return false;
}

// Splits one logical line into command segments on unquoted separators,
// tokenizes each with quote awareness, and marks comments/echo/piped-from-
// echo segments. `isPowershellOrShell` controls whether `#` starts a
// comment (PowerShell/sh) — in batch, `#` has no special meaning.
void processLine(const std::string& rawLine, bool isPowershellOrShell, std::vector<CommandSegment>& out) {
    std::string line = rawLine;
    // Drop a leading '@' (batch's per-line echo-off marker) and leading
    // whitespace; neither changes command meaning.
    std::size_t start = 0;
    while (start < line.size() && (line[start] == ' ' || line[start] == '\t')) start++;
    if (start < line.size() && line[start] == '@') start++;
    line = line.substr(start);

    std::string lowerLine = lower(line);
    std::string trimmedLower = trim(lowerLine);
    if (isCommentLine(trimmedLower, isPowershellOrShell)) {
        out.push_back(CommandSegment{{}, true, false, false});
        return;
    }

    // Split into segments on unquoted &, &&, |, ||, ; — track which
    // segments were separated by a pipe so a `echo <value>| date` pattern
    // can be recognized as piping into the date/time command.
    std::vector<std::pair<std::string, bool>> rawSegments; // (segment text, pipedIntoThisOne)
    std::string current;
    bool inSingle = false, inDouble = false;
    bool nextIsPiped = false;
    for (std::size_t i = 0; i < line.size(); i++) {
        char c = line[i];
        if (c == '\'' && !inDouble) { inSingle = !inSingle; current += c; continue; }
        if (c == '"' && !inSingle) { inDouble = !inDouble; current += c; continue; }
        if (!inSingle && !inDouble && (c == '&' || c == '|' || c == ';')) {
            bool isPipe = (c == '|');
            if (!current.empty()) rawSegments.emplace_back(current, nextIsPiped);
            current.clear();
            nextIsPiped = isPipe;
            // swallow a doubled separator (&&, ||)
            if (i + 1 < line.size() && line[i + 1] == c) i++;
            continue;
        }
        current += c;
    }
    if (!current.empty()) rawSegments.emplace_back(current, nextIsPiped);

    for (auto& [segText, piped] : rawSegments) {
        // Inline comment for PowerShell/sh: an unquoted '#' truncates the rest.
        if (isPowershellOrShell) {
            bool sInSingle = false, sInDouble = false;
            for (std::size_t i = 0; i < segText.size(); i++) {
                char c = segText[i];
                if (c == '\'' && !sInDouble) sInSingle = !sInSingle;
                else if (c == '"' && !sInSingle) sInDouble = !sInDouble;
                else if (c == '#' && !sInSingle && !sInDouble) { segText = segText.substr(0, i); break; }
            }
        }

        CommandSegment seg;
        seg.precededByPipe = piped;
        std::string tok;
        bool tInSingle = false, tInDouble = false;
        auto flush = [&]() {
            if (!tok.empty()) { seg.tokens.push_back(lower(tok)); tok.clear(); }
        };
        for (std::size_t i = 0; i < segText.size(); i++) {
            char c = segText[i];
            if (c == '\'' && !tInDouble) { tInSingle = !tInSingle; continue; }
            if (c == '"' && !tInSingle) { tInDouble = !tInDouble; continue; }
            if (!tInSingle && !tInDouble && (c == ' ' || c == '\t')) { flush(); continue; }
            tok += c;
        }
        flush();

        if (seg.tokens.empty()) continue;
        seg.isEcho = seg.tokens[0] == "echo";

        // A quoted token that itself contains embedded whitespace came from
        // a genuinely quoted span (an unquoted token can never contain a
        // raw space). Most such spans are opaque data — a commit message,
        // a label — and must stay opaque so quoting `--amend`/`push` inside
        // one doesn't false-positive. But two constructs quote a *real
        // nested command*: invoking an interpreter with an inline command
        // string (`powershell -Command "Set-Date ..."`, `cmd /c "..."`,
        // `bash -c "..."`), and batch `for /f ... in ('command') do ...`
        // command-substitution. In exactly those cases the quoted content
        // is re-split on whitespace and folded back into this segment's
        // own tokens (in addition to the merged one) so the normal
        // exact-token detectors below still see e.g. "set-date" or "log".
        bool isNestedCommandContext =
            (!seg.tokens.empty() &&
             (seg.tokens[0] == "powershell" || seg.tokens[0] == "pwsh" || seg.tokens[0] == "cmd" ||
              seg.tokens[0] == "cmd.exe" || seg.tokens[0] == "bash" || seg.tokens[0] == "sh" ||
              seg.tokens[0] == "for"));
        if (isNestedCommandContext) {
            std::vector<std::string> expansion;
            for (const auto& t : seg.tokens) {
                if (t.find(' ') == std::string::npos) continue;
                std::string word;
                for (char c : t) {
                    if (c == ' ' || c == '\t') {
                        if (!word.empty()) { expansion.push_back(word); word.clear(); }
                    } else {
                        word += c;
                    }
                }
                if (!word.empty()) expansion.push_back(word);
            }
            seg.tokens.insert(seg.tokens.end(), expansion.begin(), expansion.end());
        }

        out.push_back(std::move(seg));
    }

    // Pipe adjacency (echo piped into date/time, e.g. `echo 2024-01-01| date`)
    // is resolved by the caller in tokenizeScript(), which sees the final
    // per-line segment list in order and can mark pipedFromEcho directly.
}

std::vector<CommandSegment> tokenizeScript(const std::string& content, bool isPowershellOrShell) {
    std::string joined = joinCaretContinuations(content);
    std::vector<CommandSegment> segments;
    for (const auto& rawLine : splitLines(joined)) {
        std::vector<CommandSegment> lineSegments;
        processLine(rawLine, isPowershellOrShell, lineSegments);
        for (std::size_t i = 0; i < lineSegments.size(); i++) {
            if (i > 0 && lineSegments[i - 1].isEcho && lineSegments[i].precededByPipe) {
                lineSegments[i].pipedFromEcho = true;
            }
            segments.push_back(std::move(lineSegments[i]));
        }
    }
    return segments;
}

bool segIsReal(const CommandSegment& s) { return !s.isComment && !s.isEcho; }

bool hasToken(const CommandSegment& s, const std::string& tok) {
    return std::find(s.tokens.begin(), s.tokens.end(), tok) != s.tokens.end();
}

bool hasTokenPrefix(const CommandSegment& s, const std::string& prefix) {
    for (const auto& t : s.tokens) {
        if (t.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

// Real per-token force-push detection (see header comment): long form
// (--force, --force-with-lease[=ref]), standalone -f, or a combined
// short-option token built only from real `git push` short flags
// (f=force, u=set-upstream, q=quiet, v=verbose, n=dry-run) in either
// order (-uf / -fu).
bool isForceFlagToken(const std::string& tok) {
    if (tok.rfind("--force", 0) == 0) return true;
    if (tok == "-f") return true;
    if (tok.size() >= 2 && tok.size() <= 4 && tok[0] == '-' && tok[1] != '-') {
        bool onlyKnown = true, hasF = false;
        for (std::size_t i = 1; i < tok.size(); i++) {
            char c = tok[i];
            if (c == 'f') hasF = true;
            if (c != 'f' && c != 'u' && c != 'q' && c != 'v' && c != 'n') { onlyKnown = false; break; }
        }
        if (onlyKnown && hasF) return true;
    }
    return false;
}

bool hasForcePushCommand(const std::vector<CommandSegment>& segments) {
    for (const auto& s : segments) {
        if (!segIsReal(s)) continue;
        if (!hasToken(s, "push")) continue;
        for (const auto& tok : s.tokens) {
            if (isForceFlagToken(tok)) return true;
        }
    }
    return false;
}

bool hasAmendCommand(const std::vector<CommandSegment>& segments) {
    for (const auto& s : segments) {
        if (segIsReal(s) && hasToken(s, "--amend")) return true;
    }
    return false;
}

bool hasNoVerifyCommand(const std::vector<CommandSegment>& segments) {
    for (const auto& s : segments) {
        if (segIsReal(s) && hasToken(s, "--no-verify")) return true;
    }
    return false;
}

bool hasAddAllCommand(const std::vector<CommandSegment>& segments) {
    for (const auto& s : segments) {
        if (!segIsReal(s) || !hasToken(s, "add")) continue;
        if (hasToken(s, ".") || hasToken(s, "-a") || hasToken(s, "-all")) return true;
    }
    return false;
}

bool hasIdentityChangeCommand(const std::vector<CommandSegment>& segments) {
    for (const auto& s : segments) {
        if (!segIsReal(s) || !hasToken(s, "config")) continue;
        if (hasToken(s, "user.name") || hasToken(s, "user.email")) return true;
    }
    return false;
}

bool hasLogReconCommand(const std::vector<CommandSegment>& segments) {
    for (const auto& s : segments) {
        if (!segIsReal(s) || !hasToken(s, "log") || !hasToken(s, "-1")) continue;
        for (const auto& t : s.tokens) {
            if (t == "%ci" || t == "%ai" || t == "%an" || t == "%ae" || t == "%s" || t == "%cd" ||
                t == "%cn" || t == "%ce")
                return true;
            if (t.rfind("--format", 0) == 0 || t.rfind("--pretty", 0) == 0) return true;
        }
    }
    return false;
}

// Counts real (non-comment, non-echo) clock-manipulation command
// invocations: PowerShell Set-Date, WMIC localdatetime, w32tm, and the
// classic cmd.exe `date`/`time` commands — either given a direct argument
// or fed one via a pipe from an `echo` (the standard non-interactive way
// to answer DATE/TIME's "enter new date" prompt without a person at the
// keyboard). Bare `date /t`/`time /t` (read-only display) is explicitly
// excluded so routine logging timestamps don't count.
std::size_t countClockChangeCommands(const std::vector<CommandSegment>& segments) {
    std::size_t count = 0;
    for (const auto& s : segments) {
        if (!segIsReal(s)) continue;
        if (hasToken(s, "set-date")) { count++; continue; }
        if (hasToken(s, "wmic") && hasToken(s, "set") && hasTokenPrefix(s, "localdatetime")) { count++; continue; }
        if (hasToken(s, "w32tm") && (hasToken(s, "/set") || hasTokenPrefix(s, "/set"))) { count++; continue; }
        if (!s.tokens.empty() && (s.tokens[0] == "date" || s.tokens[0] == "time")) {
            bool readOnly = s.tokens.size() >= 2 && s.tokens[1] == "/t";
            bool hasArg = s.tokens.size() >= 2 && !readOnly;
            if (!readOnly && (hasArg || s.pipedFromEcho)) count++;
        }
    }
    return count;
}

Finding makeGitFinding(const std::string& ruleId, const std::string& name, Severity sev, Confidence conf,
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
    f.evidence = evidence;
    f.tags = std::move(tags);
    return f;
}

} // namespace

std::vector<Finding> scanGitPropagationArtifacts(const std::string& relPath, const std::string& filename,
                                                  const std::string& extensionLower,
                                                  const std::string& content) {
    std::vector<Finding> findings;
    if (!scriptExtensions().count(extensionLower)) return findings;

    bool isPowershellOrShell = (extensionLower == ".ps1" || extensionLower == ".sh");
    auto segments = tokenizeScript(content, isPowershellOrShell);

    std::size_t clockChangeCount = countClockChangeCommands(segments);
    bool hasIdentityChange = hasIdentityChangeCommand(segments);
    bool hasAddAll = hasAddAllCommand(segments);
    bool hasAmend = hasAmendCommand(segments);
    bool hasNoVerify = hasNoVerifyCommand(segments);
    bool hasForcePush = hasForcePushCommand(segments);
    bool hasLogReconSignal = hasLogReconCommand(segments);

    // Amend + a force-push are the two structural anchors of this TTP —
    // rewrite a commit, then push over any history that would otherwise
    // reject a non-fast-forward update. Neither alone is unusual (a solo
    // developer might amend-and-force-push a typo fix by hand); it is their
    // combination *inside a checked-in automation script*, especially
    // alongside clock/identity manipulation, that is the documented attack
    // shape.
    if (!(hasAmend && hasForcePush)) return findings;

    int corroboration = (hasIdentityChange ? 1 : 0) + (hasAddAll ? 1 : 0) + (hasNoVerify ? 1 : 0) +
                         (hasLogReconSignal ? 1 : 0);

    Severity severity;
    Confidence confidence;
    std::string sequenceNote;

    if (clockChangeCount >= 2) {
        severity = Severity::Critical;
        confidence = corroboration >= 1 ? Confidence::Confirmed : Confidence::High;
        sequenceNote = "system clock changed " + std::to_string(clockChangeCount) +
                       " times (consistent with save-then-restore) around a commit amend and force-push";
    } else if (clockChangeCount == 1 && corroboration >= 1) {
        severity = Severity::Critical;
        confidence = Confidence::High;
        sequenceNote = "a single system clock change plus " + std::to_string(corroboration) +
                       " corroborating signal(s) around a commit amend and force-push";
    } else if (clockChangeCount == 1) {
        severity = Severity::Critical;
        confidence = Confidence::Medium;
        sequenceNote = "a system clock change around a commit amend and force-push, with no further "
                       "corroboration";
    } else if (corroboration >= 2) {
        severity = Severity::High;
        confidence = Confidence::Medium;
        sequenceNote = std::to_string(corroboration) +
                       " corroborating signal(s) (identity change / staged-add / --no-verify / prior-"
                       "commit metadata read) around a commit amend and force-push, no clock manipulation "
                       "observed";
    } else if (corroboration == 1) {
        severity = Severity::High;
        confidence = Confidence::Low;
        sequenceNote = "one corroborating signal around a commit amend and force-push";
    } else {
        severity = Severity::Medium;
        confidence = Confidence::Low;
        sequenceNote = "a commit amend and force-push with no other corroborating signal — plausibly a "
                       "manual one-off fix captured in a script";
    }

    std::vector<std::string> tags = {"git-propagation", "history-rewrite", "correlation"};
    if (clockChangeCount > 0) tags.push_back("clock-manipulation");
    if (hasIdentityChange) tags.push_back("identity-spoofing");
    if (hasLogReconSignal) tags.push_back("metadata-recon");

    bool isCompleteSequence = clockChangeCount >= 2 && corroboration >= 3;
    std::string ruleId = "git.propagation.clock_amend_force_push_pattern";
    std::string ruleName = "Git history-rewrite propagation pattern";
    if (isCompleteSequence) {
        severity = Severity::Critical;
        confidence = Confidence::Confirmed;
        tags.push_back("GIT_HISTORY_TIME_MANIPULATION");
        ruleId = "git.propagation.history_time_manipulation";
        ruleName = "GIT_HISTORY_TIME_MANIPULATION";
    }

    findings.push_back(makeGitFinding(
        ruleId, ruleName, severity, confidence,
        "Script '" + filename + "' combines a commit --amend with a force-push (" + sequenceNote +
            "). This is the documented mechanism for making a malicious commit appear untouched in Git "
            "history. Detected via command-aware tokenization (comments/echo/quoted text excluded), not "
            "raw substring matching — campaign-independent TTP, not itself evidence of any specific "
            "attacker.",
        relPath, filename, tags));

    return findings;
}

std::vector<Finding> scanGitignoreForHiddenArtifacts(const std::string& relPath, const std::string& filename,
                                                      const std::string& content) {
    std::vector<Finding> findings;
    if (lower(filename) != ".gitignore") return findings;

    static const std::vector<std::pair<const char*, const char*>> knownArtifacts = {
        {"temp_auto_push.bat", "temp_auto_push.bat"},
        {"temp_interactive_push.bat", "temp_interactive_push.bat"},
        {"branch_structure.json", "branch_structure.json"},
        {"config.bat", "config.bat"},
    };

    auto lines = splitLines(content);
    for (const auto& [needle, label] : knownArtifacts) {
        for (std::size_t i = 0; i < lines.size(); i++) {
            std::string trimmed = trim(lines[i]);
            if (trimmed == needle) {
                findings.push_back(makeGitFinding(
                    "git.propagation.gitignore_hides_artifact",
                    "Known propagation artifact hidden via .gitignore", Severity::High, Confidence::Medium,
                    std::string(".gitignore excludes '") + label +
                        "' from `git status`, matching the documented pattern of a propagation script "
                        "hiding its own artifacts from casual review.",
                    relPath, trimmed, {"git-propagation", "concealment", "gitignore-manipulation"}));
                findings.back().line = i + 1;
            }
        }
    }
    return findings;
}

} // namespace abyss::git
