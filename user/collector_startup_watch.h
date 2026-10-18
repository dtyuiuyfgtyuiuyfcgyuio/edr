#ifndef EDR_COLLECTOR_STARTUP_WATCH_H
#define EDR_COLLECTOR_STARTUP_WATCH_H

#include <windows.h>

#include <string>
#include <utility>
#include <vector>

namespace edr {

using StartupDirectory = std::pair<std::wstring, bool>;

std::vector<StartupDirectory> CanonicalStartupDirectories(
    const std::vector<StartupDirectory>& directories, bool requireExisting);
std::vector<StartupDirectory> DiscoverProfileStartupDirectories(HKEY profileList);
std::vector<StartupDirectory> DiscoverFallbackStartupDirectories(HKEY profileList);

} // namespace edr

#endif
