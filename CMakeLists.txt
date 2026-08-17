cmake_minimum_required(VERSION 3.20)
project(abyss LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8 /EHsc /guard:cf /sdl)
    # Static MSVC runtime: the release binary must not depend on the
    # VC++ Redistributable being separately installed on the target
    # machine -- this is what "one executable, no separate runtime
    # dependency to document" actually requires in practice.
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_link_options(/DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /guard:cf)
else()
    add_compile_options(-Wall -Wextra)
endif()

add_library(abyss_core STATIC
    src/core/core.cpp
    src/crypto/sha256.cpp
    src/scanner/scanner.cpp
    src/scanner/deobfuscate.cpp
    src/rules/rules.cpp
    src/preflight/esr.cpp
    src/vscode/vscode.cpp
    src/git/git_propagation.cpp
    src/git/safe_git.cpp
    src/response/response.cpp
    src/evidence/evidence.cpp
)

target_include_directories(abyss_core PUBLIC src)

if(WIN32)
    target_link_libraries(abyss_core PUBLIC bcrypt advapi32 iphlpapi)
endif()

add_executable(abyss src/cli/main.cpp)
target_link_libraries(abyss PRIVATE abyss_core)

enable_testing()
add_executable(abyss_tests
    tests/test_main.cpp
    tests/test_core.cpp
    tests/test_sha256.cpp
    tests/test_scanner.cpp
    tests/test_rules.cpp
    tests/test_vscode.cpp
    tests/test_deobfuscate.cpp
    tests/test_response.cpp
    tests/test_safe_git.cpp
)
target_link_libraries(abyss_tests PRIVATE abyss_core)
target_include_directories(abyss_tests PRIVATE src)
add_test(NAME abyss_tests COMMAND abyss_tests)
