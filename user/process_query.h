#ifndef EDR_PROCESS_QUERY_H
#define EDR_PROCESS_QUERY_H

#include <windows.h>

#include <string>
#include <cstdint>

namespace edr {

std::string ReadProcessCommandLine(DWORD pid);

/* Resolve the full image path (e.g. C:\Windows\System32\notepad.exe) of a
 * live process via QueryFullProcessImageNameW. Returns empty string when the
 * process is gone or access is denied. Callers that only have the basename
 * (ETW Kernel-Process ImageName, Toolhelp szExeFile) should prefer this over
 * hard-coding a System32 prefix. */
std::string ResolveProcessImagePath(DWORD pid);

/* Resolve image and exact creation time from one retained process handle.
 * If the current PID instance was created after the event timestamp, reject
 * its attribution. Zero timestamp requests a current snapshot. All failures
 * clear outputs. Access denied/exited processes remain unattributed. */
bool ResolveProcessContext(DWORD pid, uint64_t eventTime100ns,
                           std::string& image, uint64_t& startTime100ns);

/* Basename (final path component, lowercased) of a resolved image path; used
 * to keep `image` comparisons stable regardless of path casing. Returns the
 * input unchanged when no path separator is present. */
std::string ImageBaseName(const std::string& imagePath);

} // namespace edr

#endif // EDR_PROCESS_QUERY_H
