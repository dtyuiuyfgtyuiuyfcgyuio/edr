#ifndef EDR_COLLECTOR_REG_WATCH_H
#define EDR_COLLECTOR_REG_WATCH_H

#include <windows.h>

#include <atomic>
#include <cstddef>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "collector.h"

namespace edr {

using RegistrySnapshot = std::map<std::string, std::string>;

enum class RegistrySnapshotStatus { Complete, Missing, Failed };

struct RegistrySnapshotReadResult {
    RegistrySnapshotStatus status = RegistrySnapshotStatus::Failed;
    RegistrySnapshot values;
};

struct RegistrySnapshotLimits {
    size_t maxTargets = 2080;
    size_t maxDynamicTargets = 2048;
    size_t maxEnumeratedValues = 16384;
    size_t maxValuesPerTarget = 4096;
    size_t maxTotalValues = 65536;
    size_t maxPayloadBytesPerTarget = 16 * 1024 * 1024;
    size_t maxTotalPayloadBytes = 64 * 1024 * 1024;
};

/* A target commits atomically: Failed and over-budget candidates leave the
 * previous baseline untouched. Missing is a complete, empty snapshot. */
class RegistrySnapshotTracker {
public:
    explicit RegistrySnapshotTracker(RegistrySnapshotLimits limits = {});

    bool Apply(const std::string& targetId, RegistrySnapshotStatus status,
               const RegistrySnapshot& candidate, bool dynamicTarget,
               bool emitChanges,
               std::vector<std::pair<std::string, std::string>>& changed,
               bool preserveMissing = false);
    bool ReconcileDynamicTargets(const std::set<std::string>& targetIds,
                                 bool enumerationComplete);
    bool HasTarget(const std::string& targetId) const;
    std::set<std::string> KnownDynamicTargets() const;

private:
    struct RetainedTarget {
        RegistrySnapshot values;
        size_t payloadBytes = 0;
        bool dynamic = false;
    };

    RegistrySnapshotLimits m_limits;
    std::map<std::string, RetainedTarget> m_targets;
    size_t m_totalValues = 0;
    size_t m_totalPayloadBytes = 0;
};

/* Runtime health is published through atomics so health readers never inspect
 * worker-owned registry handles, target flags, or snapshot maps. */
class RegistryWatchHealth {
public:
    void ConfigureTargets(size_t configured) noexcept;
    void RecordReadFailure() noexcept;
    void RecordNotificationArmFailure() noexcept;
    void PublishCoverage(size_t activeWatches, size_t missingTargets,
                         size_t currentReadFailures,
                         size_t currentArmFailures) noexcept;
    CollectorHealthSnapshot ApplyTo(CollectorHealthSnapshot sample) const;

private:
    std::atomic<uint64_t> m_configuredTargets{0};
    std::atomic<uint64_t> m_activeWatches{0};
    std::atomic<uint64_t> m_missingTargets{0};
    std::atomic<uint64_t> m_currentReadFailures{0};
    std::atomic<uint64_t> m_currentArmFailures{0};
    std::atomic<uint64_t> m_readFailures{0};
    std::atomic<uint64_t> m_notificationArmFailures{0};
};

RegistrySnapshotReadResult ReadRegistrySnapshotValuesChecked(
    HKEY key, const std::string& prefix,
    const std::vector<std::wstring>& valueFilter,
    const RegistrySnapshotLimits& limits = {});

void ReadRegistrySnapshotValues(HKEY key, const std::string& prefix,
                                 const std::vector<std::wstring>& valueFilter,
                                 RegistrySnapshot& out);

/* Static watcher target shape, exposed so tests can align rule coverage
 * with the exact keys/values the collector monitors. */
struct RegWatchTargetSummary {
    std::string prefix;                   /* UTF-8 registry path prefix */
    std::vector<std::string> valueNames;  /* UTF-8; empty = unfiltered */
    bool watchSubtree = false;
};

const std::vector<RegWatchTargetSummary>& RegWatchTargetSummaries();

} // namespace edr

#endif
