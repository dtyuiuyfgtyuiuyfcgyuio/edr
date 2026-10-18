#include "process_query.h"

#include <cstdint>
#include <vector>

#include "config.h"

namespace edr {
namespace {

using NtQueryInformationProcessFn = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG,
                                                   PULONG);

struct UnicodeStringNative {
    USHORT length;
    USHORT maximumLength;
    PWSTR buffer;
};

constexpr ULONG kProcessCommandLineInformation = 60;
constexpr ULONG kMaximumCommandLineBytes = 64 * 1024;

} // namespace

std::string ReadProcessCommandLine(DWORD pid) {
    if (pid == 0) return {};

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return {};

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto query = ntdll ? reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(ntdll, "NtQueryInformationProcess")) : nullptr;
    if (!query) {
        CloseHandle(process);
        return {};
    }

    ULONG needed = 0;
    query(process, kProcessCommandLineInformation, nullptr, 0, &needed);
    if (needed < sizeof(UnicodeStringNative) ||
        needed > kMaximumCommandLineBytes - sizeof(wchar_t)) {
        CloseHandle(process);
        return {};
    }

    std::vector<unsigned char> storage(needed + sizeof(wchar_t), 0);
    ULONG returned = 0;
    LONG status = query(process, kProcessCommandLineInformation, storage.data(),
                        static_cast<ULONG>(storage.size()), &returned);
    CloseHandle(process);
    if (status < 0) return {};

    const auto* commandLine =
        reinterpret_cast<const UnicodeStringNative*>(storage.data());
    if (!commandLine->buffer || commandLine->length == 0 ||
        commandLine->length % sizeof(wchar_t) != 0) return {};

    uintptr_t begin = reinterpret_cast<uintptr_t>(storage.data());
    uintptr_t end = begin + storage.size();
    uintptr_t text = reinterpret_cast<uintptr_t>(commandLine->buffer);
    if (text < begin || text > end || commandLine->length > end - text)
        return {};

    return WideToUtf8(commandLine->buffer,
                      commandLine->length / sizeof(wchar_t));
}

std::string ResolveProcessImagePath(DWORD pid) {
    if (pid == 0) return {};

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return {};

    wchar_t path[MAX_PATH];
    DWORD size = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameW(process, 0, path, &size);
    CloseHandle(process);
    if (!ok || size == 0) return {};

    return WideToUtf8(path, size);
}

bool ResolveProcessContext(DWORD pid, uint64_t eventTime100ns,
                           std::string& image, uint64_t& startTime100ns) {
    image.clear();
    startTime100ns = 0;
    if (pid == 0) return false;
    std::vector<wchar_t> path(32768);
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return false;
    FILETIME created{}, exited{}, kernel{}, user{};
    DWORD size = static_cast<DWORD>(path.size());
    const BOOL haveTime = GetProcessTimes(process, &created, &exited, &kernel, &user);
    const BOOL haveImage = haveTime && QueryFullProcessImageNameW(process, 0, path.data(), &size);
    CloseHandle(process);
    if (!haveTime || !haveImage || size == 0) return false;
    const uint64_t start = (static_cast<uint64_t>(created.dwHighDateTime) << 32) |
                          created.dwLowDateTime;
    if (start == 0 || (eventTime100ns != 0 && start > eventTime100ns)) return false;
    image = WideToUtf8(path.data(), size);
    if (image.empty()) return false;
    startTime100ns = start;
    return true;
}

std::string ImageBaseName(const std::string& imagePath) {
    if (imagePath.empty()) return {};

    /* Find the last separator (backslash or forward slash). */
    size_t sep = imagePath.rfind('\\');
    if (sep == std::string::npos) sep = imagePath.rfind('/');
    if (sep == std::string::npos) return imagePath; /* already a basename */

    return imagePath.substr(sep + 1);
}

} // namespace edr
