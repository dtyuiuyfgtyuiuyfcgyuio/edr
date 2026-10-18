#include "dispatch_timing_tests.h"

#include <cstdio>
#include <exception>

int main() {
    try {
        RunDispatchTimingTests();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[dispatch_timing] FAILED: %s\n", e.what());
        return 1;
    } catch (...) {
        std::fprintf(stderr, "[dispatch_timing] FAILED: unknown exception\n");
        return 1;
    }
    return 0;
}
