#include <exception>
#include <iostream>
#include "telemetry_contract_tests.h"

int main() {
    try {
        RunTelemetryContractTests();
        std::cout << "telemetry contract tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
