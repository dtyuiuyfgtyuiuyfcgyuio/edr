/*
 * collector_critical_process.h - Critical security process protection.
 *
 * Polls for configured critical processes (e.g. Windows Defender) and emits
 * CRITICAL_PROCESS events when a protected process disappears. Detects
 * security tool tampering / defense evasion (MITRE T1562.001).
 */
#ifndef EDR_COLLECTOR_CRITICAL_PROCESS_H
#define EDR_COLLECTOR_CRITICAL_PROCESS_H

#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <functional>
#include <set>
#include <string>
#include <vector>

namespace edr {

class ICollector;

enum class CriticalProcessSnapshotStatus { Complete, Failed };

struct CriticalProcessSnapshot {
    CriticalProcessSnapshotStatus status = CriticalProcessSnapshotStatus::Failed;
    std::set<std::string> images;
};

using CriticalProcessQuery = std::function<CriticalProcessSnapshot()>;

/* Narrow Toolhelp seam: production and native failure tests use this reader. */
struct CriticalProcessToolhelpApi {
    std::function<HANDLE()> createSnapshot;
    std::function<BOOL(HANDLE, LPPROCESSENTRY32W)> first;
    std::function<BOOL(HANDLE, LPPROCESSENTRY32W)> next;
    std::function<DWORD()> lastError;
    std::function<void(HANDLE)> close;

    static CriticalProcessToolhelpApi Native();
};

CriticalProcessSnapshot ReadCriticalProcessSnapshot(
    const CriticalProcessToolhelpApi& api, size_t maxProcesses = 65536);
bool CriticalProcessConfigIsValid(const std::vector<std::string>& images);

ICollector* CreateCriticalProcessCollector(
    uint32_t pollMs, uint32_t missingThreshold,
    const std::vector<std::string>& protectedImages);
ICollector* CreateCriticalProcessCollector(
    uint32_t pollMs, uint32_t missingThreshold,
    const std::vector<std::string>& protectedImages,
    CriticalProcessQuery query);

} // namespace edr

#endif /* EDR_COLLECTOR_CRITICAL_PROCESS_H */
