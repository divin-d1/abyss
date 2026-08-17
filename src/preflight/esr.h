#pragma once

#include <string>
#include <vector>

namespace abyss::preflight {

// One entry in the Execution Surface Registry: a tool whose configuration
// file is auto-executed by developer tooling (see README.md).
// ESR entries are DATA (rules/execution-surfaces/*.esr); this struct and its
// loader are the ENGINE and must not need new code to support a new tool.
struct ExecutionSurface {
    std::string id;
    std::string tool;
    std::vector<std::string> patterns; // exact filenames, e.g. "next.config.js"
    std::string risk;                  // free-text classification, e.g. "executable-config"
    bool autoload = false;
    std::string sourceFile;
};

struct EsrLoadResult {
    std::vector<ExecutionSurface> surfaces;
    std::vector<std::string> errors;
};

EsrLoadResult loadExecutionSurfaces(const std::string& dir);

class ExecutionSurfaceRegistry {
public:
    explicit ExecutionSurfaceRegistry(std::vector<ExecutionSurface> surfaces)
        : surfaces_(std::move(surfaces)) {}

    const std::vector<ExecutionSurface>& surfaces() const { return surfaces_; }

    // Returns the matching surface for an exact filename (case-insensitive),
    // or nullptr if the filename is not a known autoload execution surface.
    const ExecutionSurface* match(const std::string& filename) const;

private:
    std::vector<ExecutionSurface> surfaces_;
};

} // namespace abyss::preflight
