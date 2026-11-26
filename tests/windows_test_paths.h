#ifndef EDR_WINDOWS_TEST_PATHS_H
#define EDR_WINDOWS_TEST_PATHS_H

#include <windows.h>

#include <cstdio>
#include <stdexcept>
#include <string>

inline std::wstring LongWindowsTestTempPath() {
    wchar_t temp[MAX_PATH] = {};
    const DWORD length = GetTempPathW(MAX_PATH, temp);
    if (!length || length >= MAX_PATH)
        throw std::runtime_error("temporary directory is unavailable");

    // Some Windows runners expose TEMP through an 8.3 alias, while
    // collectors and quarantine metadata use resolved long paths.
    wchar_t resolved[MAX_PATH] = {};
    const DWORD resolvedLength = GetLongPathNameW(temp, resolved, MAX_PATH);
    if (!resolvedLength || resolvedLength >= MAX_PATH)
        throw std::runtime_error("could not resolve long temporary directory path");
    std::wstring result(resolved, resolvedLength);
    if (result.back() != L'\\') result.push_back(L'\\');
    if (result != temp)
        std::fprintf(stderr, "[windows-tests] normalized temporary directory path\n");
    return result;
}

#endif // EDR_WINDOWS_TEST_PATHS_H
