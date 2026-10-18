#include "correlation_rollup_tests.h"

#include <cstdio>
#include <exception>

int main() {
    try {
        RunCorrelationRollupTests();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[correlation_rollup] FAILED: %s\n", e.what());
        return 1;
    } catch (...) {
        std::fprintf(stderr, "[correlation_rollup] FAILED: unknown exception\n");
        return 1;
    }
    std::fprintf(stderr, "[correlation_rollup] ok\n");
    return 0;
}
