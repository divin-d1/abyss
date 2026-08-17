#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "core/core.h"
#include "preflight/esr.h"
#include "rules/rules.h"

namespace abyss::scanner {

// ---------------------------------------------------------------------------
// Structural file-type validation (section 21: WOFF/WOFF2/TTF/OTF/PNG/JPEG/
// GIF/PDF/ZIP/PE). Magic/signature checks only — Abyss never parses
// untrusted files with a third-party library.
// ---------------------------------------------------------------------------

enum class FileKind {
    Unknown, Woff, Woff2, Ttf, Otf, Png, Jpeg, Gif, Pdf, Zip, Pe
};

std::string toString(FileKind k);

// Identifies the file kind from its magic bytes only (content, not extension).
FileKind detectMagic(const std::uint8_t* data, std::size_t len);

// Returns the FileKind(s) an extension like ".woff2" is expected to contain.
// Extension must be lowercase and include the leading dot.
std::vector<FileKind> expectedKindsForExtension(const std::string& extensionLower);

// ---------------------------------------------------------------------------
// Shannon entropy
// ---------------------------------------------------------------------------

double shannonEntropyBits(const std::uint8_t* data, std::size_t len);

// ---------------------------------------------------------------------------
// Native text/behavioral heuristics. Ported conceptually from polin-guard's
// weighted-signal model (MIT-licensed; see the attribution note in
// rules/core/thresholds.rules) and reimplemented
// from scratch in C++ — thresholds are data (ScanThresholds), the scanning
// logic is native code.
// ---------------------------------------------------------------------------

struct ScanThresholds {
    std::size_t oversizedLineLength = 1000;
    std::size_t concealmentGapLength = 50;     // run of horizontal whitespace mid-line
    std::size_t escapeDensityMinCount = 25;    // \xNN / \uNNNN escapes in one line
    std::size_t longTokenLength = 120;         // unbroken non-whitespace run
    double highEntropyThreshold = 4.8;         // bits/char, Shannon
    std::size_t highEntropyMinLineLength = 200;
    // Real encoded/obfuscated payloads are overwhelmingly a single unbroken
    // token (that is what makes them high-entropy over the whole line in
    // the first place) — legitimate dense-but-readable lines (long Tailwind
    // className strings, JSX with many short attributes) still have normal
    // word-spacing. A line with more than this fraction of horizontal
    // whitespace is exempted from the entropy check even if it crosses
    // highEntropyThreshold, since long_token already separately catches the
    // single-unbroken-run shape this detector is meant to complement, not
    // duplicate.
    double highEntropyMaxWhitespaceRatio = 0.10;

    static ScanThresholds withDefaults() { return ScanThresholds{}; }
};

// Loads threshold overrides from a `.rules`-style file containing a single
// [thresholds] block (see rules/core/thresholds.rules). Missing file or keys
// fall back to defaults silently — thresholds are tuning, not correctness.
ScanThresholds loadThresholds(const std::string& path);

// Runs all native structural/behavioral text detectors against one file's
// decoded text content. `relPath` is used only to populate Finding::filePath.
std::vector<Finding> scanTextHeuristics(const std::string& relPath, const std::string& content,
                                         const ScanThresholds& thresholds);

// Detects credential-shaped values (tokens, private keys, password
// assignments) committed to a text file. Evidence is always redacted —
// never the matched value itself — and placeholder/example values (low
// character variety, or containing words like "example"/"changeme") are
// filtered out before a finding is raised.
std::vector<Finding> scanCredentialExposure(const std::string& relPath, const std::string& content);

// Detects a binary-extension masquerade: a file whose extension implies a
// known binary format (font/image/etc.) but whose magic bytes don't match,
// combined with a check for readable script markers in its body. This is the
// native structural check behind the "fake font" family of TTPs.
std::vector<Finding> scanBinaryExtensionMasquerade(const std::string& relPath,
                                                    const std::string& extensionLower,
                                                    const std::vector<std::uint8_t>& bytes);

// Detects concealed non-ASCII control/formatting characters (zero-width
// space/joiners, bidi overrides, variation selectors, private-use code
// points) that render invisibly in most editors. This is a general
// concealment technique, not attributed to any single campaign.
std::vector<Finding> scanInvisibleUnicode(const std::string& relPath, const std::string& content);

// ---------------------------------------------------------------------------
// Repository discovery + orchestration
// ---------------------------------------------------------------------------

struct DiscoveredFile {
    std::string absolutePath;
    std::string relativePath; // forward-slash normalized, relative to scan root
    std::string filename;
    std::string extensionLower; // includes leading dot, e.g. ".js"; empty if none
    bool isSymlink = false;     // the directory-entry itself is a symlink/reparse point
};

struct RepositoryDiscovery {
    std::vector<DiscoveredFile> files;
    bool isGitRepository = false;
    std::size_t skippedLargeFiles = 0;
    std::size_t skippedUnreadable = 0;
    // A symlink/junction/reparse point whose resolved target falls outside
    // the scan root was not followed (see README.md "Filesystem
    // safety"). Each entry is the *link's* path (never the escaped target,
    // which may point somewhere sensitive we don't want to echo unasked).
    std::vector<std::string> symlinkEscapesSkipped;
    // A directory could not be listed (permission denied, race condition,
    // I/O error) — discovery continues past it rather than aborting.
    std::vector<std::string> directoryErrors;
};

// Walks `root` recursively. Descends into `.git` only far enough to confirm
// its presence (git object/ref internals are handled by src/git, not here).
// Symlinks/junctions/reparse points are never followed if their resolved
// target lies outside `root` (see RepositoryDiscovery::symlinkEscapesSkipped).
// A single unreadable/errored directory does not abort the walk — every
// other reachable path is still discovered, and the omission is recorded.
RepositoryDiscovery discoverRepository(const std::string& root);

struct ScanOptions {
    ScanThresholds thresholds = ScanThresholds::withDefaults();
    std::size_t maxFileBytes = 64ull * 1024 * 1024;
    bool computeHashes = true;

    // Called after each file is analyzed, with the running totals and the
    // number of worker threads this scan is actually using (1 for a
    // single-threaded scan). There is no file-count limit and
    // node_modules/vendor/build directories are deliberately not skipped (a
    // compromised dependency inside node_modules is exactly the shape of
    // attack this project targets — see README.md's threat model), so a
    // large project can take a real amount of time. This exists so a caller
    // can show that the scan is still working instead of appearing to hang,
    // and that the reported thread count is what's genuinely running, not
    // a claim. Optional; a null callback (the default) costs one branch per
    // file. May be called concurrently from multiple threads — must be
    // safe to call that way (see main.cpp's ScanProgressPrinter for the
    // reference implementation, which serializes with a mutex).
    std::function<void(std::size_t filesAnalyzed, std::size_t filesDiscovered, std::size_t threadsUsed)> onProgress;
};

struct ScanCoverage {
    std::size_t filesDiscovered = 0;
    std::size_t filesAnalyzed = 0;
    std::size_t filesTruncated = 0;
    std::size_t filesUnreadable = 0;
    std::size_t symlinkEscapesSkipped = 0;
    std::size_t directoryErrors = 0;
    // A file whose size or modification time differed between the
    // pre-read and post-read stat — it was being written to (or replaced)
    // concurrently with the scan, so the bytes actually analyzed may not
    // reflect any single consistent version of the file. See
    // scanner::scanRepository's per-file TOCTOU check.
    std::size_t filesChangedDuringScan = 0;
    bool gitDetected = false;

    // How many worker threads actually ran this scan's per-file analysis
    // (1 means the scan ran single-threaded — either because it was small,
    // or because available memory/CPU cores constrained it to one). See
    // scanRepository's thread-count selection in scanner.cpp.
    std::size_t threadsUsed = 1;

    // False whenever anything prevented full analysis of the requested
    // scope, OR the analysis itself might not reflect a single consistent
    // state (unreadable files, truncated files, directories that couldn't
    // be listed, symlink/junction escapes that were refused, files that
    // changed mid-read). A scan report built from incomplete coverage must
    // never be presented as a complete clearance — see README.md
    // and evidence::computeVerdict.
    bool isComplete() const {
        return filesUnreadable == 0 && filesTruncated == 0 && directoryErrors == 0 &&
               symlinkEscapesSkipped == 0 && filesChangedDuringScan == 0;
    }
};

struct ScanReport {
    std::vector<Finding> findings;
    ScanCoverage coverage;
};

// Full static scan of a single repository/directory: discovery, magic
// validation, binary-extension masquerade, text heuristics, invisible
// unicode, IOC rule evaluation, and execution-surface-aware weighting.
ScanReport scanRepository(const std::string& root, const rules::RuleEngine& ruleEngine,
                           const preflight::ExecutionSurfaceRegistry& esr,
                           const ScanOptions& options);

} // namespace abyss::scanner
