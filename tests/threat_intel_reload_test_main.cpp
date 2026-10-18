#include <cstdio>
#include <exception>

#include "threat_intel_detector_tests.h"

int main(int argc, char** argv) {
    try {
        if (argc > 2) {
            std::fprintf(stderr, "usage: edr_threat_intel_reload_tests [rules.json]\n");
            return 1;
        }
        RunThreatIntelDetectorTests();
        if (argc == 2) RunThreatIntelCidrRuleTests(argv[1]);
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "[threat_intel] %s\n", error.what());
        return 1;
    }
}
