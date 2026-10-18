#include "collector_runtime_health_tests.h"

#include <exception>
#include <iostream>

int main() {
    try {
        RunCollectorRuntimeHealthTests();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    std::cout << "collector runtime health tests passed\n";
    return 0;
}
