#include "event_log_bookmark_tests.h"
#include <exception>
#include <iostream>

int main() {
    try { RunEventLogBookmarkTests(); }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    std::cout << "event log bookmark tests passed\n";
    return 0;
}
