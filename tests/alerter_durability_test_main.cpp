#include "alerter_durability_tests.h"
#include <exception>
#include <iostream>

int main() {
    try { RunAlerterDurabilityTests(); }
    catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    std::cout << "alerter durability tests passed\n";
    return 0;
}
