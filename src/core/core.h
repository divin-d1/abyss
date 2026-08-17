#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <variant>
#include <vector>

namespace abyss {

// ---------------------------------------------------------------------------
// Finding taxonomy
// ---------------------------------------------------------------------------

enum class Severity { Info, Low, Medium, High, Critical };
enum class Confidence { Unknown, Low, Medium, High, Confirmed };
enum class RuleType { Ioc, Structural, Behavior, Correlation };

std::string toString(Severity s);
std::string toString(Confidence c);
std::string toString(RuleType t);
std::optional<Severity> severityFromString(const std::string& s);
std::optional<Confidence> confidenceFromString(const std::string& s);
std::optional<RuleType> ruleTypeFromString(const std::string& s);

// A single piece of evidence produced by a detector or rule.
struct Finding {
    std::string findingId;      // unique per emitted finding (sequential)
    std::string ruleId;         // stable rule identifier, e.g. "polinrider.config.marker.v1"
    std::string ruleName;
    RuleType type = RuleType::Behavior;
    Severity severity = Severity::Info;
    Confidence confidence = Confidence::Unknown;
    std::string description;
    std::string filePath;                 // path relative to scan root, forward-slash normalized
    std::optional<std::size_t> line;
    std::string evidence;                 // short, truncated excerpt — never full secret material
    std::vector<std::string> tags;
    std::string campaign;                 // e.g. "PolinRider-like"; empty if no attribution made
    Confidence attributionConfidence = Confidence::Unknown;
};

// ---------------------------------------------------------------------------
// Minimal JSON value + tolerant (JSONC) parser
//
// Abyss does not depend on a third-party JSON library. This parser is
// intentionally small: it exists to read untrusted developer-authored files
// (tasks.json, package.json, extension manifests) as inert data, and to
// support Abyss's own structured JSONL evidence output. It tolerates
// `//` and `/* */` comments and trailing commas because VS Code's own
// tasks.json/settings.json are JSONC, not strict JSON.
// ---------------------------------------------------------------------------

class JsonValue;
using JsonArray = std::vector<JsonValue>;
using JsonObject = std::vector<std::pair<std::string, JsonValue>>; // preserves order, allows lookup

class JsonValue {
public:
    enum class Kind { Null, Bool, Number, String, Array, Object };

    JsonValue() : kind_(Kind::Null) {}
    static JsonValue makeNull() { return JsonValue(); }
    static JsonValue makeBool(bool b);
    static JsonValue makeNumber(double n);
    static JsonValue makeString(std::string s);
    static JsonValue makeArray(JsonArray a);
    static JsonValue makeObject(JsonObject o);

    Kind kind() const { return kind_; }
    bool isNull() const { return kind_ == Kind::Null; }
    bool isObject() const { return kind_ == Kind::Object; }
    bool isArray() const { return kind_ == Kind::Array; }
    bool isString() const { return kind_ == Kind::String; }
    bool isBool() const { return kind_ == Kind::Bool; }
    bool isNumber() const { return kind_ == Kind::Number; }

    bool asBool(bool def = false) const;
    double asNumber(double def = 0.0) const;
    const std::string& asString() const;
    std::string asStringOr(const std::string& def) const;
    const JsonArray& asArray() const;
    const JsonObject& asObject() const;

    // Object field lookup; returns nullptr if absent or not an object.
    const JsonValue* find(const std::string& key) const;

private:
    Kind kind_;
    bool boolVal_ = false;
    double numVal_ = 0.0;
    std::string strVal_;
    std::shared_ptr<JsonArray> arrVal_;
    std::shared_ptr<JsonObject> objVal_;
};

struct JsonParseResult {
    bool ok = false;
    JsonValue value;
    std::string error;
};

// Resource limits enforced while parsing untrusted JSON/JSONC. Defaults are
// generous for legitimate config/manifest files but bound worst-case
// memory/CPU against an adversarial input (deeply nested arrays, huge
// object/array fan-out, multi-gigabyte payloads). See README.md
// "Parser hardening".
struct JsonParseLimits {
    std::size_t maxInputBytes = 32ull * 1024 * 1024;
    int maxDepth = 64;
    std::size_t maxNodes = 200000;
};

// Parses JSON or JSONC (comments + trailing commas tolerated) text.
// Hardened: requires EOF (only whitespace/comments) after the root value,
// rejects duplicate object keys, rejects unterminated strings/block
// comments, and enforces JsonParseLimits. Never throws and never reads
// past `text`'s bounds on malformed input — `ok=false` with a diagnostic
// `error` is the failure contract.
JsonParseResult parseJson(const std::string& text, const JsonParseLimits& limits = JsonParseLimits{});

// Minimal JSON writer used for JSONL evidence output. Produces compact,
// single-line, strictly valid JSON (no comments, no trailing commas).
std::string jsonEscape(const std::string& s);
std::string findingToJsonLine(const Finding& f);

// ---------------------------------------------------------------------------
// Block format — shared by the rule pack format (rules/*.rules) and the
// Execution Surface Registry (rules/execution-surfaces/*.esr).
//
// A tiny, deterministic, dependency-free format Abyss owns:
//
//   [section]
//   key=value
//   key=value another instance of the same key appends to a list
//   # comment
//
// This is deliberately not YAML/JSON/INI-compatible in edge cases; it is
// only expressive enough for rule and registry data.
// ---------------------------------------------------------------------------

struct Block {
    std::string section;
    std::multimap<std::string, std::string> fields;

    // Returns the first value for key, or def if absent.
    std::string get(const std::string& key, const std::string& def = "") const;
    // Returns all values for key (supports repeated key=value lines).
    std::vector<std::string> getAll(const std::string& key) const;
    // Splits a single value on ';' into a trimmed, non-empty list.
    static std::vector<std::string> splitList(const std::string& value);
    bool has(const std::string& key) const;
};

struct BlockParseResult {
    bool ok = false;
    std::vector<Block> blocks;
    std::string error;
};

// Resource limits enforced while parsing a `.rules`/`.esr` file — the same
// concern as JsonParseLimits, for the block format. Defaults are generous
// for legitimate rule packs but bound worst-case memory/CPU against an
// adversarial or corrupted file.
struct BlockParseLimits {
    std::size_t maxInputBytes = 4ull * 1024 * 1024;
    std::size_t maxLines = 100000;
    std::size_t maxBlocks = 20000;
    std::size_t maxFieldsPerBlock = 2000;
    std::size_t maxLineLength = 8192;
};

BlockParseResult parseBlocks(const std::string& text, const BlockParseLimits& limits = BlockParseLimits{});

// ---------------------------------------------------------------------------
// Byte / text utilities
// ---------------------------------------------------------------------------

std::string toHex(const std::uint8_t* data, std::size_t len);
std::string trim(const std::string& s);
std::vector<std::string> splitLines(const std::string& text);

// Reads a file fully into memory as raw bytes. Returns false on failure.
// `truncated` is set true if the file exceeded maxBytes and was cut short —
// callers must report reduced coverage rather than silently ignoring it.
bool readFileBytes(const std::string& path, std::vector<std::uint8_t>& out,
                    bool& truncated, std::size_t maxBytes = 64ull * 1024 * 1024);

std::string bytesToStringLossy(const std::vector<std::uint8_t>& bytes);

// Process-wide monotonically increasing finding id, e.g. "F000042".
// Not persisted across runs; evidence JSONL consumers should key on
// (ruleId, filePath, line) for cross-run identity instead.
std::string nextFindingId();

// Reads an environment variable safely. Windows uses the native bounded
// GetEnvironmentVariable API; other platforms use std::getenv. Returns empty
// when the variable is unset, empty or exceeds the Windows environment limit.
std::string getEnvVar(const std::string& name);

// Strict, checked integer/double parsing to replace atoi/atoll/atof
// throughout the codebase, which silently return 0 on *any* invalid input
// (negative-as-poisoned, overflow, trailing junk, "NaN", empty string —
// all indistinguishable from a legitimate "0"). Returns std::nullopt for
// anything that isn't a fully-consumed, in-range, finite number — callers
// must then explicitly decide the fallback/rejection behavior rather than
// silently trusting an ambiguous 0.
std::optional<long long> parseStrictInt(const std::string& s);
std::optional<double> parseStrictDouble(const std::string& s);

// True iff `child`'s filesystem path components start with all of
// `ancestor`'s components. Shared containment check used by both
// repository discovery (symlink/junction escape refusal) and rule-pack
// manifest verification (rejecting manifest entries that resolve outside
// the rules directory). Deliberately not std::mismatch(a.begin(),a.end(),
// b.begin()) — that is undefined behavior when `b` is shorter than `a`.
bool pathStartsWith(const std::filesystem::path& child, const std::filesystem::path& ancestor);

// True iff `p` is a Windows reparse point (symlink, NTFS junction, or any
// other reparse tag) — checked directly via FILE_ATTRIBUTE_REPARSE_POINT
// because std::filesystem::is_symlink does not reliably classify every
// reparse point type (notably junctions, which use a different reparse
// tag than symlinks). Always false on non-Windows builds.
bool isReparsePoint(const std::filesystem::path& p);

// Converts a filesystem path to a UTF-8 std::string. Use this everywhere
// instead of std::filesystem::path::string(): on Windows, path::string()
// converts via the process's ANSI codepage and THROWS std::system_error
// for any filename containing a character that codepage can't represent
// (most non-Latin scripts, many accented Latin letters, emoji) -- and
// since Abyss's job is walking arbitrary real developer machines and
// repositories, such a filename is not a hypothetical: it is what actually
// crashed a real system-scan run (an uncaught exception reaching abort(),
// reported by Windows as exception 0xc0000409). This converts the path's
// native UTF-16 representation directly to UTF-8 via WideCharToMultiByte,
// which is lossless for all valid UTF-16 (including surrogate pairs) and
// never throws for this reason. On non-Windows, path's native encoding is
// already treated as UTF-8, so this is just path.string().
std::string pathToUtf8(const std::filesystem::path& p);

// Strips ANSI/control escape sequences and raw control bytes from
// untrusted text (filenames, evidence excerpts, rule/campaign strings)
// before it reaches a terminal or log. Printable text (including UTF-8
// continuation bytes >=0x80) passes through unchanged; C0 control bytes
// (0x00-0x1F) other than tab and 0x7F DEL are replaced with `?`, and a
// bare ESC (0x1B) — the lead byte of every ANSI/VT escape sequence — is
// dropped along with the shortest plausible CSI/OSC sequence following it
// so a malicious filename can't repaint or manipulate the user's terminal.
// Also truncates to a bounded length so a single field can't flood output.
std::string sanitizeForOutput(const std::string& s, std::size_t maxLen = 4096);

// Redacts likely secret *values* (access tokens, API keys, passwords,
// Authorization headers, private-key PEM blocks, connection strings, cloud
// credential formats, .env-style KEY=VALUE where the key name suggests a
// secret) found within otherwise-legitimate evidence text — file content,
// commands, arguments, config values — before it is ever included in
// console or JSON output. Unlike sanitizeForOutput() (which strips control/
// escape bytes for terminal safety), this targets the *meaning* of the
// text: a matched secret's value is replaced with a fixed-width
// `[REDACTED:<kind>]` placeholder while the surrounding context (the key
// name, the sentence, the rule that matched) is preserved, so a finding
// remains investigable without ever printing the credential itself.
std::string redactSecrets(const std::string& s);

// One match against the same pattern table redactSecrets() uses.
struct SecretMatch {
    std::string kind;      // e.g. "aws-access-key", "github-token"
    std::size_t position;  // byte offset of `value` within the scanned string
    std::string value;     // the matched value itself — see warning below
};

// Finds every secret-pattern match in `s`, with position and the matched
// value. `value` is real secret material: callers may use it for internal
// classification (e.g. filtering out placeholder/example values) but must
// never place it directly into a finding, report, or any other output —
// always redact the surrounding text with redactSecrets() first.
std::vector<SecretMatch> detectSecretMatches(const std::string& s);

} // namespace abyss
