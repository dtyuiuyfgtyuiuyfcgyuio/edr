#include <cstdio>
#include <exception>

#include "behavior_baseline_detector_tests.h"

int main(int argc, char** argv) {
    try {
        if (argc > 2) {
            std::fprintf(stderr,
                "usage: edr_behavior_baseline_tests [rules.json]\n");
            return 1;
        }
        RunBehaviorBaselineTests(argc == 2 ? argv[1] : nullptr);
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "[behavior_baseline] %s\n", error.what());
        return 1;
    }
}
