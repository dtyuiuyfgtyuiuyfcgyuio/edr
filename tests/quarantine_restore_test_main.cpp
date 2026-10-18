#include "quarantine_restore_tests.h"
#include <exception>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--native") {
            std::string reason;
            const int result = RunQuarantineRestoreNativeTests(reason);
            if (!reason.empty()) std::cout << reason << '\n';
            return result;
        }
        if (argc != 1) return 2;
        RunQuarantineRestoreTests();
    }
    catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    std::cout << "quarantine restore tests passed\n";
    return 0;
}
