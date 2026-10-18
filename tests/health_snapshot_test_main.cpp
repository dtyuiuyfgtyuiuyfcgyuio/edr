#include "health_snapshot_tests.h"
#include <exception>
#include <iostream>

int main() {
    try {
        RunHealthSnapshotTests();
        std::cout << "health snapshot tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
