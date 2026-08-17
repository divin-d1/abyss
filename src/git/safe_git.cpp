#include "git/safe_git.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <random>
#include <regex>
#include <sstream>
#include <thread>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <csignal>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace abyss::git {
namespace {

std::vector<std::string> hardenedArgs(const std::vector<std::string>& args) {
    std::vector<std::string> out = {
#if defined(_WIN32)
        "-c", "core.hooksPath=NUL",
#else
        "-c", "core.hooksPath=/dev/null",
#endif
        "-c", "protocol.file.allow=never",
        "-c", "protocol.ext.allow=never",
        "-c", "submodule.recurse=false",
        "-c", "core.safecrlf=true",
        "-c", "advice.detachedHead=false"
    };
    out.insert(out.end(), args.begin(), args.end());
    return out;
}

std::string uniqueSuffix() {
    std::random_device rd;
    std::uniform_int_distribution<unsigned long long> dist;
    std::ostringstream out;
    out << std::hex << dist(rd) << dist(rd);
    return out.str();
}

bool appendBounded(std::string& output, const char* data, std::size_t size, std::size_t maxBytes) {
    if (output.size() >= maxBytes) return false;
    const std::size_t count = std::min(size, maxBytes - output.size());
    output.append(data, count);
    return count == size;
}

#if defined(_WIN32)
std::wstring widen(const std::string& input) {
    if (input.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                                   static_cast<int>(input.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                        static_cast<int>(input.size()), result.data(), size);
    return result;
}

std::wstring quoteWindowsArg(const std::wstring& arg) {
    if (arg.find_first_of(L" \t\"") == std::wstring::npos) return arg;
    std::wstring out = L"\"";
    std::size_t slashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'\"') { out.append(slashes * 2 + 1, L'\\'); out.push_back(c); slashes = 0; continue; }
        out.append(slashes, L'\\'); slashes = 0; out.push_back(c);
    }
    out.append(slashes * 2, L'\\');
    out.push_back(L'\"');
    return out;
}

// CreateProcessW's implicit executable search (when lpApplicationName is
// null and the command line names a bare file) checks the *calling*
// process's current directory before it checks PATH. If Abyss is invoked
// from inside a repository (a normal `cd project && abyss pull .` workflow)
// and that repository ships its own git.exe, the implicit search would
// launch the repository's binary instead of the real one. Resolving an
// absolute path here — from well-known install locations and PATH entries
// only, never the current directory — and passing it as lpApplicationName
// removes that search entirely.
std::wstring tryGitAt(const std::wstring& dir) {
    if (dir.empty()) return {};
    std::wstring candidate = dir;
    if (candidate.back() != L'\\') candidate += L'\\';
    candidate += L"git.exe";
    DWORD attrs = GetFileAttributesW(candidate.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) return candidate;
    return {};
}

std::wstring computeGitExecutablePath() {
    for (const wchar_t* envVar : {L"ProgramFiles", L"ProgramFiles(x86)", L"ProgramW6432"}) {
        wchar_t buf[MAX_PATH]{};
        DWORD n = GetEnvironmentVariableW(envVar, buf, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) continue;
        for (const wchar_t* suffix : {L"\\Git\\cmd", L"\\Git\\bin"}) {
            auto found = tryGitAt(std::wstring(buf) + suffix);
            if (!found.empty()) return found;
        }
    }

    std::wstring pathVar;
    DWORD need = GetEnvironmentVariableW(L"PATH", nullptr, 0);
    if (need > 0) {
        pathVar.resize(need);
        DWORD got = GetEnvironmentVariableW(L"PATH", pathVar.data(), need);
        pathVar.resize(got);
    }
    std::size_t start = 0;
    while (start <= pathVar.size()) {
        std::size_t sep = pathVar.find(L';', start);
        std::wstring dir = pathVar.substr(start, sep == std::wstring::npos ? std::wstring::npos : sep - start);
        // Only absolute drive paths are trusted. Relative entries (including
        // a bare "." some PATH configurations add) are skipped so a
        // repository directory can never satisfy this search by being the
        // process current directory.
        if (dir.size() >= 3 && dir[1] == L':' && (dir[2] == L'\\' || dir[2] == L'/')) {
            auto found = tryGitAt(dir);
            if (!found.empty()) return found;
        }
        if (sep == std::wstring::npos) break;
        start = sep + 1;
    }
    return {};
}

// Function-local static initialization is thread-safe (C++11 magic
// statics), so this is safe to call concurrently without extra locking.
const std::wstring& resolveGitExecutablePath() {
    static const std::wstring resolved = computeGitExecutablePath();
    return resolved;
}
#endif

ProcessResult runDirect(const std::string& workingDirectory,
                        const std::vector<std::string>& arguments,
                        std::chrono::seconds timeout,
                        std::size_t maxOutputBytes) {
    ProcessResult result;
#if defined(_WIN32)
    const std::wstring& gitPath = resolveGitExecutablePath();
    if (gitPath.empty()) {
        result.error = "cannot locate git.exe in a trusted install location or PATH entry "
                       "(the current directory is never searched)";
        return result;
    }

    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE readPipe = nullptr, writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) { result.error = "CreatePipe failed"; return result; }
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    std::wstring command = quoteWindowsArg(gitPath);
    for (const auto& arg : arguments) command += L" " + quoteWindowsArg(widen(arg));
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = writePipe; startup.hStdError = writePipe;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION process{};
    std::wstring cwd = widen(workingDirectory);
    BOOL started = CreateProcessW(gitPath.c_str(), mutableCommand.data(), nullptr, nullptr, TRUE,
                                  CREATE_NO_WINDOW, nullptr,
                                  cwd.empty() ? nullptr : cwd.c_str(), &startup, &process);
    CloseHandle(writePipe);
    if (!started) { CloseHandle(readPipe); result.error = "CreateProcessW(git.exe) failed"; return result; }
    result.started = true;

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::array<char, 4096> buffer{};
    for (;;) {
        DWORD available = 0;
        if (PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) && available > 0) {
            DWORD read = 0;
            if (ReadFile(readPipe, buffer.data(), static_cast<DWORD>(std::min<std::size_t>(buffer.size(), available)), &read, nullptr) && read)
                appendBounded(result.output, buffer.data(), read, maxOutputBytes);
        }
        DWORD wait = WaitForSingleObject(process.hProcess, 25);
        if (wait == WAIT_OBJECT_0) break;
        if (std::chrono::steady_clock::now() >= deadline) {
            TerminateProcess(process.hProcess, 124);
            result.timedOut = true;
            break;
        }
    }
    while (true) {
        DWORD read = 0;
        if (!ReadFile(readPipe, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) || read == 0) break;
        appendBounded(result.output, buffer.data(), read, maxOutputBytes);
    }
    DWORD exitCode = 1;
    GetExitCodeProcess(process.hProcess, &exitCode);
    result.exitCode = static_cast<int>(exitCode);
    CloseHandle(readPipe); CloseHandle(process.hThread); CloseHandle(process.hProcess);
#else
    int pipefd[2];
    if (pipe(pipefd) != 0) { result.error = "pipe failed"; return result; }
    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); result.error = "fork failed"; return result; }
    if (pid == 0) {
        if (!workingDirectory.empty() && chdir(workingDirectory.c_str()) != 0) _exit(126);
        dup2(pipefd[1], STDOUT_FILENO); dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]); close(pipefd[1]);
        std::vector<std::string> owned; owned.push_back("git");
        owned.insert(owned.end(), arguments.begin(), arguments.end());
        std::vector<char*> argv;
        for (auto& value : owned) argv.push_back(value.data());
        argv.push_back(nullptr);
        execvp("git", argv.data());
        _exit(127);
    }
    result.started = true;
    close(pipefd[1]);
    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::array<char, 4096> buffer{};
    int status = 0;
    for (;;) {
        ssize_t count = read(pipefd[0], buffer.data(), buffer.size());
        if (count > 0) appendBounded(result.output, buffer.data(), static_cast<std::size_t>(count), maxOutputBytes);
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) break;
        if (std::chrono::steady_clock::now() >= deadline) {
            kill(pid, SIGKILL); waitpid(pid, &status, 0); result.timedOut = true; break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    while (true) {
        ssize_t count = read(pipefd[0], buffer.data(), buffer.size());
        if (count <= 0) break;
        appendBounded(result.output, buffer.data(), static_cast<std::size_t>(count), maxOutputBytes);
    }
    close(pipefd[0]);
    result.exitCode = result.timedOut ? 124 : (WIFEXITED(status) ? WEXITSTATUS(status) : 128);
#endif
    return result;
}

bool containsDangerousConfig(const std::string& text) {
    // Git config syntax allows arbitrary whitespace (including none) around
    // '=' — "smudge=cmd", "smudge = cmd", and "smudge\t=\tcmd" are all
    // valid and equivalent. The original fixed-string "smudge =" (exactly
    // one space each side) missed the no-space and multi-space forms
    // entirely, which is a real evasion gap for a check that exists
    // specifically to catch a maliciously-configured filter/hook override.
    // Bounded quantifier (no unbounded repetition on overlapping classes),
    // consistent with every other regex in this project that runs on
    // untrusted content.
    static const std::regex dangerous(
        R"(\b(?:smudge|clean|process|hookspath|sshcommand|uploadpack|receivepack)\s{0,8}=)",
        std::regex::ECMAScript | std::regex::icase);
    return std::regex_search(text, dangerous);
}

} // namespace

ProcessResult runGit(const std::string& workingDirectory, const std::vector<std::string>& arguments,
                     std::chrono::seconds timeout, std::size_t maxOutputBytes) {
    return runDirect(workingDirectory, hardenedArgs(arguments), timeout, maxOutputBytes);
}

bool remoteUrlAllowed(const std::string& remote, std::string& error) {
    if (remote.empty() || remote.size() > 4096) { error = "remote URL is empty or too long"; return false; }
    std::string lower = remote;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower.rfind("https://", 0) == 0 || lower.rfind("ssh://", 0) == 0 ||
        (lower.find('@') != std::string::npos && lower.find(':') != std::string::npos && lower.find("://") == std::string::npos)) return true;
    error = "only HTTPS and SSH remotes are accepted; local/file/ext helpers are blocked";
    return false;
}

bool repositoryConfigSafe(const std::string& repository, std::string& error) {
    fs::path config = fs::path(repository) / ".git" / "config";
    std::ifstream in(config, std::ios::binary);
    if (!in) { error = "cannot read local Git configuration"; return false; }
    std::ostringstream contents; contents << in.rdbuf();
    if (containsDangerousConfig(contents.str())) {
        error = "local Git configuration contains an executable filter, hook override, custom SSH command, or custom transport program";
        return false;
    }
    return true;
}

StagedOperation prepareClone(const std::string& remote, const std::string& destination) {
    StagedOperation op;
    if (!remoteUrlAllowed(remote, op.error)) return op;
    std::error_code ec;
    if (fs::exists(destination, ec)) { op.error = "destination already exists"; return op; }
    fs::path stage = fs::path(destination).parent_path() /
                     (fs::path(destination).filename().string() + ".abyss-stage-" + uniqueSuffix());
    auto clone = runGit(fs::path(destination).parent_path().string(),
                        {"clone", "--no-checkout", "--no-recurse-submodules", "--", remote, stage.string()},
                        std::chrono::seconds(600));
    op.output = clone.output;
    if (!clone.started || clone.timedOut || clone.exitCode != 0) {
        op.error = clone.error.empty() ? "staged git clone failed" : clone.error;
        return op;
    }
    if (!repositoryConfigSafe(stage.string(), op.error)) return op;
    auto checkout = runGit(stage.string(), {"checkout", "--force", "--detach", "HEAD"});
    op.output += checkout.output;
    if (!checkout.started || checkout.timedOut || checkout.exitCode != 0) {
        op.error = "inert checkout into staging failed";
        return op;
    }
    op.ok = true; op.stagePath = stage.string(); op.targetRef = "HEAD";
    return op;
}

bool finalizeClone(const StagedOperation& operation, const std::string& destination,
                   bool allow, std::string& message) {
    if (!operation.ok || operation.stagePath.empty()) { message = "clone staging is incomplete"; return false; }
    if (!allow) { message = "incoming repository was blocked; inert staging copy preserved at " + operation.stagePath; return false; }
    std::error_code ec;
    // Re-check immediately before the rename, not just at prepareClone's
    // start: staging (clone + scan) can take a long time on a large
    // repository, and fs::rename silently replaces an existing file at
    // destination with no warning — without this check, anything created
    // at that path during the staging window would be destroyed with no
    // trace.
    if (fs::exists(destination, ec)) {
        message = "clone passed preflight, but destination now exists (created during staging) — refusing to "
                 "overwrite it; the verified clone remains at " + operation.stagePath;
        return false;
    }
    ec.clear();
    fs::rename(operation.stagePath, destination, ec);
    if (ec) { message = "scan allowed the clone but final rename failed: " + ec.message(); return false; }
    message = "clone passed preflight and was published at " + destination;
    return true;
}

StagedOperation preparePull(const std::string& repository) {
    StagedOperation op;
    if (!repositoryConfigSafe(repository, op.error)) return op;
    auto upstream = runGit(repository, {"rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"});
    if (upstream.exitCode != 0) { op.error = "current branch has no readable upstream"; op.output = upstream.output; return op; }
    op.targetRef = upstream.output;
    while (!op.targetRef.empty() && (op.targetRef.back() == '\r' || op.targetRef.back() == '\n')) op.targetRef.pop_back();
    if (op.targetRef.empty() || op.targetRef.find_first_of(" \t\r\n") != std::string::npos) { op.error = "upstream reference is invalid"; return op; }
    auto fetch = runGit(repository, {"fetch", "--prune", "--no-recurse-submodules", "--", "origin"}, std::chrono::seconds(600));
    op.output += fetch.output;
    if (fetch.exitCode != 0) { op.error = "fetch failed; working tree was not changed"; return op; }

    // Pin the exact commit right after fetch, and stage/scan/merge that SHA
    // specifically rather than the symbolic ref name from here on. The
    // symbolic name (e.g. "origin/main") can move — a concurrent fetch
    // elsewhere, a scheduled task — between when this scan happens and when
    // finalizePull's merge runs; resolving once here and using the SHA
    // everywhere after guarantees the commit that was actually scanned is
    // the same one that gets merged, not whatever the ref happens to point
    // to later.
    auto resolve = runGit(repository, {"rev-parse", "--verify", op.targetRef + "^{commit}"});
    op.output += resolve.output;
    std::string resolvedSha = resolve.output;
    while (!resolvedSha.empty() && (resolvedSha.back() == '\r' || resolvedSha.back() == '\n')) resolvedSha.pop_back();
    if (resolve.exitCode != 0 || resolvedSha.empty() ||
        resolvedSha.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
        op.error = "could not resolve upstream to a concrete commit";
        return op;
    }
    op.resolvedSha = resolvedSha;

    fs::path stage = fs::path(repository).parent_path() /
                     (fs::path(repository).filename().string() + ".abyss-pull-stage-" + uniqueSuffix());
    auto worktree = runGit(repository, {"worktree", "add", "--detach", "--no-checkout", stage.string(), op.resolvedSha});
    op.output += worktree.output;
    if (worktree.exitCode != 0) { op.error = "could not create detached pull staging tree"; return op; }
    auto checkout = runGit(stage.string(), {"checkout", "--force", "--detach", op.resolvedSha});
    op.output += checkout.output;
    if (checkout.exitCode != 0) { op.error = "could not materialize fetched tree for scanning"; return op; }
    op.ok = true; op.stagePath = stage.string();
    return op;
}

bool finalizePull(const std::string& repository, const StagedOperation& operation,
                  bool allow, std::string& message) {
    if (!operation.ok || operation.targetRef.empty() || operation.resolvedSha.empty()) {
        message = "pull staging is incomplete";
        return false;
    }
    if (!allow) { message = "incoming pull was blocked; current branch is unchanged and staging evidence remains at " + operation.stagePath; return false; }
    auto removeStage = runGit(repository, {"worktree", "remove", "--force", operation.stagePath});
    if (removeStage.exitCode != 0) { message = "incoming tree passed but staging cleanup failed; current branch was not changed"; return false; }
    // Merges the exact SHA captured in preparePull, not the symbolic ref
    // name — see StagedOperation::resolvedSha for why: the ref can move
    // between when this was scanned and now, and merging by name would
    // then fast-forward to different, unscanned content.
    auto merge = runGit(repository, {"merge", "--ff-only", operation.resolvedSha});
    if (merge.exitCode != 0) { message = "incoming tree passed but cannot be fast-forwarded safely; resolve manually\n" + merge.output; return false; }
    message = "incoming tree passed preflight and the branch was fast-forwarded to " + operation.resolvedSha;
    return true;
}

ProcessResult timeline(const std::string& repository, std::size_t limit) {
    return runGit(repository, {"log", "--date=iso-strict", "--format=%H|%P|%aI|%cI|%an|%ae|%s", "-n", std::to_string(limit)});
}

ProcessResult graph(const std::string& repository, std::size_t limit) {
    return runGit(repository, {"log", "--graph", "--decorate", "--all", "--oneline", "-n", std::to_string(limit)});
}

StagedOperation prepareRecovery(const std::string& repository, const std::string& commit,
                                const std::string& destination) {
    StagedOperation op;
    if (commit.empty() || commit.size() > 128 || commit.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
        op.error = "recovery commit must be a hexadecimal object id";
        return op;
    }
    std::error_code ec;
    if (fs::exists(destination, ec)) { op.error = "recovery destination already exists"; return op; }
    auto verify = runGit(repository, {"cat-file", "-e", commit + "^{commit}"});
    if (verify.exitCode != 0) { op.error = "selected recovery commit does not exist"; op.output = verify.output; return op; }
    auto worktree = runGit(repository, {"worktree", "add", "--detach", destination, commit});
    op.output = worktree.output;
    if (worktree.exitCode != 0) { op.error = "could not materialize recovery worktree"; return op; }
    op.ok = true; op.stagePath = destination; op.targetRef = commit;
    return op;
}

} // namespace abyss::git
