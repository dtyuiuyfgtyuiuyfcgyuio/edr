#include "etw_health_tests.h"

#include <exception>
#include <iostream>

int main() {
    try {
        RunEtwHealthTests();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    std::cout << "ETW health tests passed\n";
    return 0;
}
