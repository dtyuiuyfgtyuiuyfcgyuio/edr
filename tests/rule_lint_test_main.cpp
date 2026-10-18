#include "rule_lint_tests.h"

#include <exception>
#include <iostream>

int main() {
    try {
        RunRuleLintTests();
        std::cout << "rule lint tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
