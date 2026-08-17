#include "preflight/esr.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "core/core.h"

namespace abyss::preflight {

namespace fs = std::filesystem;

namespace {
std::string lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return r;
}
} // namespace

EsrLoadResult loadExecutionSurfaces(const std::string& dir) {
    EsrLoadResult result;
    std::error_code ec;
    if (!fs::exists(dir, ec)) return result;
    for (auto it = fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;
        if (!it->is_regular_file(ec)) continue;
        if (it->path().extension() != ".esr") continue;

        std::ifstream f(it->path(), std::ios::binary);
        if (!f) { result.errors.push_back(it->path().string() + ": could not open"); continue; }
        std::ostringstream ss;
        ss << f.rdbuf();
        auto parsed = parseBlocks(ss.str());
        if (!parsed.ok) { result.errors.push_back(it->path().string() + ": " + parsed.error); continue; }

        for (const auto& b : parsed.blocks) {
            if (b.section != "execution-surface") continue;
            ExecutionSurface surface;
            surface.id = b.get("id");
            surface.tool = b.get("tool");
            surface.patterns = Block::splitList(b.get("patterns"));
            surface.risk = b.get("risk");
            surface.autoload = lower(b.get("autoload", "false")) == "true";
            surface.sourceFile = it->path().string();
            if (surface.id.empty() || surface.patterns.empty()) {
                result.errors.push_back(it->path().string() + ": execution-surface missing id/patterns");
                continue;
            }
            result.surfaces.push_back(std::move(surface));
        }
    }
    return result;
}

const ExecutionSurface* ExecutionSurfaceRegistry::match(const std::string& filename) const {
    std::string lf = lower(filename);
    for (const auto& s : surfaces_) {
        for (const auto& p : s.patterns) {
            if (lower(p) == lf) return &s;
        }
    }
    return nullptr;
}

} // namespace abyss::preflight
