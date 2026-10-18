#include <exception>
#include <iostream>
#include "detector_tests.h"
#include "lolbin_chain_detector_tests.h"
#include "correlation_engine_tests.h"

int main() {
    try {
        RunAttackChainDetectorTests();
        RunLolbinChainDetectorTests();
        RunCorrelationEngineTests();
        std::cout << "behavior contract tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
