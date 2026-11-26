#ifndef EDR_QUARANTINE_TEST_PATHS_H
#define EDR_QUARANTINE_TEST_PATHS_H

#include <windows.h>

#include <cstdio>
#include <stdexcept>
#include <string>

inline std::wstring LongQuarantineTestTempPath() {
    wchar_t temp[MAX_PATH] = {};
    const DWORD length = GetTempPathW(MAX_PATH, temp);
    if (!length || length >= MAX_PATH)
        throw std::runtime_error("temporary directory is unavailable");

    // Some Windows runners expose TEMP through an 8.3 alias. Quarantine
    // stores resolved long paths and restore checks the exact directory.
    wchar_t resolved[MAX_PATH] = {};
    const DWORD resolvedLength = GetLongPathNameW(temp, resolved, MAX_PATH);
    if (!resolvedLength || resolvedLength >= MAX_PATH)
        throw std::runtime_error("could not resolve long temporary directory path");
    std::wstring result(resolved, resolvedLength);
    if (result.back() != L'\\') result.push_back(L'\\');
    if (result != temp)
        std::fprintf(stderr, "[quarantine-test] normalized temporary directory path\n");
    return result;
}

#endif // EDR_QUARANTINE_TEST_PATHS_H
