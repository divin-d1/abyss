#include "test_harness.h"

#include <exception>
#include <iostream>

namespace abyss::test {

std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}

namespace {
bool g_currentTestFailed = false;
int g_totalFailures = 0;
} // namespace

bool& currentTestFailed() { return g_currentTestFailed; }

void recordFailure(const std::string& file, int line, const std::string& expr) {
    std::cerr << "    FAILED: " << expr << " at " << file << ":" << line << "\n";
    g_currentTestFailed = true;
    g_totalFailures++;
}

} // namespace abyss::test

int main() {
    using namespace abyss::test;
    int total = 0, passed = 0;
    for (auto& tc : registry()) {
        currentTestFailed() = false;
        std::cout << "[ RUN  ] " << tc.name << "\n";
        try {
            tc.fn();
        } catch (const std::exception& e) {
            std::cerr << "    FAILED: uncaught exception: " << e.what() << "\n";
            currentTestFailed() = true;
            g_totalFailures++;
        } catch (...) {
            std::cerr << "    FAILED: uncaught exception (unknown type)\n";
            currentTestFailed() = true;
            g_totalFailures++;
        }
        total++;
        if (currentTestFailed()) {
            std::cout << "[ FAIL ] " << tc.name << "\n";
        } else {
            passed++;
            std::cout << "[ OK   ] " << tc.name << "\n";
        }
    }
    std::cout << "\n" << passed << "/" << total << " tests passed\n";
    return passed == total ? 0 : 1;
}
