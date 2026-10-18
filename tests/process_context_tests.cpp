#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <stdexcept>
#include <string>
#include "process_query.h"

int main() {
    try {
        FILETIME created{}, exited{}, kernel{}, user{}, now{};
        if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return 2;
        GetSystemTimePreciseAsFileTime(&now);
        const uint64_t birth = (uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        const uint64_t timestamp = (uint64_t(now.dwHighDateTime) << 32) | now.dwLowDateTime;
        std::string image;
        uint64_t start = 0;
        if (!edr::ResolveProcessContext(GetCurrentProcessId(), timestamp, image, start) ||
            image.empty() || start != birth)
            throw std::runtime_error("live process image/creation context missing");
        if (edr::ResolveProcessContext(GetCurrentProcessId(), birth - 1, image, start) ||
            !image.empty() || start != 0)
            throw std::runtime_error("process born after event incorrectly attributed");
        image = "stale"; start = 123;
        if (edr::ResolveProcessContext(0, timestamp, image, start) || !image.empty() || start != 0)
            throw std::runtime_error("PID zero did not clear context");
        image = "stale"; start = 123;
        if (edr::ResolveProcessContext(MAXDWORD, timestamp, image, start) || !image.empty() || start != 0)
            throw std::runtime_error("inaccessible process did not clear context");
        std::puts("process context tests passed");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
