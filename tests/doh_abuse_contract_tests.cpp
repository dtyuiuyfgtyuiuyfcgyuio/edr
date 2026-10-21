#include "doh_abuse_detector_tests.h"

#include <exception>
#include <iostream>

int main() {
    try {
        RunDohAbuseDetectorTests();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
