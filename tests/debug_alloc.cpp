// debug_alloc.cpp - Minimal test to isolate bad allocation in native_tests
// Compile: cl /EHsc /MD /Iuser /I. debug_alloc.cpp user/rule_engine.cpp user/json_lite.cpp /Febuild/debug_alloc.exe
// Run from build dir: debug_alloc.exe
#include <windows.h>
#include <stdio.h>
#include <string>
#include <stdexcept>

extern "C" {
    __declspec(dllimport) void* __cdecl malloc(size_t);
    __declspec(dllimport) void __cdecl free(void*);
}

int main() {
    std::fprintf(stderr, "[debug_alloc] Starting...\n");
    fflush(stderr);

    // Test 1: bare minimum regex
    try {
        std::fprintf(stderr, "[debug_alloc] Test 1: std::regex simple...\n");
        std::regex re("(?:powershell|rundll32)");
        std::fprintf(stderr, "[debug_alloc] Test 1 OK\n");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[debug_alloc] Test 1 FAIL: %s\n", e.what());
        return 1;
    }

    // Test 2: load rules.json via RuleEngine (external linkage)
    try {
        std::fprintf(stderr, "[debug_alloc] Test 2: RuleEngine LoadFromFile...\n");
        // Cannot include rule_engine.h here due to circular deps - will do separate test
        std::fprintf(stderr, "[debug_alloc] Test 2 SKIP (needs linkage)\n");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[debug_alloc] Test 2 FAIL: %s\n", e.what());
        return 2;
    }

    // Test 3: large vector allocation
    try {
        std::fprintf(stderr, "[debug_alloc] Test 3: large vector...\n");
        std::vector<std::string> v;
        v.reserve(100000);
        for (int i = 0; i < 100000; ++i) v.emplace_back("test" + std::to_string(i));
        std::fprintf(stderr, "[debug_alloc] Test 3 OK (size=%zu)\n", v.size());
    } catch (const std::bad_alloc& e) {
        std::fprintf(stderr, "[debug_alloc] Test 3 bad_alloc: %s\n", e.what());
        return 3;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[debug_alloc] Test 3 FAIL: %s\n", e.what());
        return 3;
    }

    std::fprintf(stderr, "[debug_alloc] ALL TESTS PASSED\n");
    return 0;
}