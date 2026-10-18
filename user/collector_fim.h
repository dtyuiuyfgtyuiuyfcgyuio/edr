/*
 * collector_fim.h - File integrity monitoring collector.
 *
 * Monitors configured sensitive files (hosts, system executables, etc.) and
 * emits FILE_INTEGRITY events when their content (SHA-256), size, or
 * presence changes. Detects file tampering (MITRE T1565.001).
 */
#ifndef EDR_COLLECTOR_FIM_H
#define EDR_COLLECTOR_FIM_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace edr {

class ICollector;

enum class FimSnapshotStatus { Complete, Missing, Failed };

struct FimSnapshot {
    FimSnapshotStatus status = FimSnapshotStatus::Failed;
    uint32_t statusCode = 0;
    uint64_t size = 0;
    std::string sha256;
    bool oversized = false;
};

using FimSnapshotQuery = std::function<FimSnapshot(
    const std::string& utf8Path, uint64_t maxFileBytes)>;

ICollector* CreateFimCollector(uint32_t pollMs,
                               uint64_t maxFileBytes,
                               std::vector<std::string> watchFiles);
ICollector* CreateFimCollector(uint32_t pollMs,
                               uint64_t maxFileBytes,
                               std::vector<std::string> watchFiles,
                               FimSnapshotQuery query);

} // namespace edr

#endif /* EDR_COLLECTOR_FIM_H */
