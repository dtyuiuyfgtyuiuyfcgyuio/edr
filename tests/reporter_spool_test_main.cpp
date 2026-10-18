#include "reporter_spool_tests.h"
#include <exception>
#include <iostream>

int main() {
    try { RunReporterSpoolTests(); }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    std::cout << "reporter spool tests passed\n";
    return 0;
}
