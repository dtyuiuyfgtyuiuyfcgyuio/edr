/*
 * collector_hook_scan.h - Periodic hook persistence surface scanner.
 *
 * Complements the live registry watch collector (which covers IFEO
 * Debugger changes in real time) by periodically enumerating the full
 * hook-persistence surface, including keys nobody watches live:
 *   - HKLM ...\Image File Execution Options\<image>\Debugger values
 *   - HKCU  SOFTWARE\Classes\CLSID\<clsid>\InprocServer32|LocalServer32
 *     default values (the COM hijack autorun vector)
 *
 * Each pass diffs against the previous snapshot and emits one
 * EDR_EVT_REG_WRITE event per new or changed value with source
 * "hook_scan". Enumeration is bounded by maxEntries per pass so a huge
 * user hive cannot pin the worker.
 */
#ifndef EDR_COLLECTOR_HOOK_SCAN_H
#define EDR_COLLECTOR_HOOK_SCAN_H

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <thread>

#include "collector.h"
#include "collector_runtime_health.h"

namespace edr {

class EventBus;

using HookScanValues = std::map<std::string, std::string>;

enum class HookScanSnapshotStatus { Complete, Missing, Failed };
enum class HookScanSurface { Ifeo, HkcuCom };

struct HookScanTargetSnapshot {
    HookScanSnapshotStatus status = HookScanSnapshotStatus::Failed;
    HookScanValues values;
};

struct HookScanRootSnapshot {
    HookScanSnapshotStatus status = HookScanSnapshotStatus::Failed;
    std::map<std::string, HookScanTargetSnapshot> targets;
};

struct HookScanSnapshot {
    HookScanRootSnapshot ifeo;
    HookScanRootSnapshot hkcuCom;
};

struct HookScanReadLimits {
    size_t maxTargets = 65536;
    size_t maxValueBytes = 64 * 1024;
    size_t maxTargetPayloadBytes = 256 * 1024;
    size_t maxRootPayloadBytes = 32 * 1024 * 1024;
};

struct HookScanBudgetLimits {
    size_t maxTargets = 65536;
    size_t maxValues = 65536;
    size_t maxBytes = 64 * 1024 * 1024;
};

/* Shared production accounting helpers; the byte estimate includes target and
 * value strings plus conservative map-node charges, including empty targets. */
size_t EstimateHookScanTargetCharge(const std::string& targetId,
                                    const HookScanValues& values,
                                    size_t* componentsExamined = nullptr);

class HookScanRetainedBudget {
public:
    explicit HookScanRetainedBudget(HookScanBudgetLimits limits = {});
    bool Set(const std::string& targetId, HookScanValues values,
             std::vector<std::pair<std::string, std::string>>* changed = nullptr,
             bool emitNew = false);
    bool SetUnknown(const std::string& targetId, bool emitOnRecovery = false);
    bool Erase(const std::string& targetId);
    void ErasePrefix(const std::string& prefix,
                     const std::atomic<bool>* stop = nullptr);
    void EraseAbsent(const std::string& prefix,
                     const std::map<std::string, HookScanTargetSnapshot>& present,
                     const std::atomic<bool>* stop = nullptr);
    const HookScanValues* Find(const std::string& targetId) const;
    size_t TargetCount() const noexcept { return m_targets.size(); }
    size_t ValueCount() const noexcept { return m_values; }
    size_t PayloadBytes() const noexcept { return m_bytes; }
    size_t CandidateItemsExamined() const noexcept { return m_candidateItemsExamined; }

private:
    struct Entry {
        HookScanValues values;
        size_t charge = 0;
        bool known = true;
        bool emitOnRecovery = false;
    };
    HookScanBudgetLimits m_limits;
    std::map<std::string, Entry> m_targets;
    size_t m_values = 0;
    size_t m_bytes = 0;
    size_t m_candidateItemsExamined = 0;
};

using HookScanQuery = std::function<HookScanSnapshot()>;

/* Exposed native seam for bounded tests against a caller-owned registry root. */
HookScanRootSnapshot ReadHookScanRegistryRoot(
    HKEY hive, const std::wstring& rootPath, const std::string& utf8Prefix,
    HookScanSurface surface, size_t maxTargets,
    const HookScanReadLimits& limits = {});

class HookScanCollector : public ICollector {
public:
    HookScanCollector(uint32_t pollSeconds, size_t maxEntries);
    HookScanCollector(uint32_t pollSeconds, size_t maxEntries,
                      HookScanQuery query);

    ~HookScanCollector() override;

    bool Start(EventBus* bus) override;
    void Stop() override;
    CollectorHealthSnapshot GetHealthSnapshot() const override;

private:
    void ScanAndDiff();

    uint32_t m_pollMs;
    size_t m_maxEntries;
    HookScanQuery m_query;
    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_explicitStop{true};
    std::atomic<bool> m_workerFailed{false};
    std::atomic<uint64_t> m_failedCurrent{0};
    std::atomic<uint64_t> m_missingCurrent{0};
    std::atomic<uint64_t> m_pendingCurrent{0};
    std::atomic<uint64_t> m_successesAtStart{0};
    CollectorRuntimeHealth m_health;
};

ICollector* CreateHookScanCollector(uint32_t pollSeconds,
                                    size_t maxEntries);
ICollector* CreateHookScanCollector(uint32_t pollSeconds,
                                    size_t maxEntries, HookScanQuery query);

} // namespace edr

#endif /* EDR_COLLECTOR_HOOK_SCAN_H */
