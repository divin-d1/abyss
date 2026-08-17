#pragma once

// Abyss's internal lightweight test harness. No Catch2/GoogleTest/etc — see
// the v0.1 dependency constraints in README.md. Tests self-
// register at static-init time and test_main.cpp runs them all, exiting
// non-zero on any failure (CI backstop philosophy).

#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace abyss::test {

struct TestCase {
    std::string name;
    std::function<void()> fn;
};

std::vector<TestCase>& registry();
void recordFailure(const std::string& file, int line, const std::string& expr);
bool& currentTestFailed();

struct Registrar {
    Registrar(const std::string& name, std::function<void()> fn) { registry().push_back({name, std::move(fn)}); }
};

// Locates the repository's fixtures/ directory regardless of the test
// binary's working directory (build tree layout varies by generator).
inline std::string fixturesDir() {
    namespace fs = std::filesystem;
    fs::path start = fs::current_path();
    for (fs::path p = start; ; p = p.parent_path()) {
        std::error_code ec;
        if (fs::exists(p / "fixtures", ec) && fs::exists(p / "CMakeLists.txt", ec)) return (p / "fixtures").string();
        if (p == p.parent_path()) break;
    }
    return "fixtures";
}

inline std::string rulesDir() {
    namespace fs = std::filesystem;
    fs::path start = fs::current_path();
    for (fs::path p = start; ; p = p.parent_path()) {
        std::error_code ec;
        if (fs::exists(p / "rules", ec) && fs::exists(p / "CMakeLists.txt", ec)) return (p / "rules").string();
        if (p == p.parent_path()) break;
    }
    return "rules";
}

inline std::string readFixtureText(const std::string& name) {
    std::ifstream f(fixturesDir() + "/" + name, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

inline std::vector<std::uint8_t> readFixtureBytes(const std::string& name) {
    std::ifstream f(fixturesDir() + "/" + name, std::ios::binary | std::ios::ate);
    std::vector<std::uint8_t> out;
    if (!f) return out;
    auto size = f.tellg();
    out.resize((std::size_t)size);
    f.seekg(0);
    if (size > 0) f.read(reinterpret_cast<char*>(out.data()), size);
    return out;
}

} // namespace abyss::test

#define ABYSS_CONCAT_(a, b) a##b
#define ABYSS_CONCAT(a, b) ABYSS_CONCAT_(a, b)

#define ABYSS_TEST(name)                                                                                   \
    static void ABYSS_CONCAT(abyss_test_fn_, __LINE__)();                                                  \
    static ::abyss::test::Registrar ABYSS_CONCAT(abyss_test_reg_, __LINE__)(                                \
        name, ABYSS_CONCAT(abyss_test_fn_, __LINE__));                                                     \
    static void ABYSS_CONCAT(abyss_test_fn_, __LINE__)()

#define ABYSS_CHECK(cond)                                                                                   \
    do {                                                                                                    \
        if (!(cond)) ::abyss::test::recordFailure(__FILE__, __LINE__, #cond);                               \
    } while (0)

#define ABYSS_CHECK_EQ(a, b)                                                                                \
    do {                                                                                                    \
        if (!((a) == (b))) ::abyss::test::recordFailure(__FILE__, __LINE__, #a " == " #b);                  \
    } while (0)
