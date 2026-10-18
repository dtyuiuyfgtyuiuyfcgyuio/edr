/*
 * system_snapshot.h - Emergency-response system state snapshot.
 *
 * Collects process list, network connections, listening ports, services,
 * shares, and startup persistence and prints a text report. Read-only.
 */
#ifndef EDR_SYSTEM_SNAPSHOT_H
#define EDR_SYSTEM_SNAPSHOT_H

#include <cstdint>
#include <string>

namespace edr {

struct SnapshotOptions {
    uint32_t processTreeDepth = 5;
    bool includeServices = true;
    bool includeShares = true;
    bool includeRunKeys = true;
    bool includeConnections = true;
};

/* Build a human-readable snapshot report. */
std::string BuildSystemSnapshotText(const SnapshotOptions& options = {});

/* Build a JSON summary of the snapshot contents. */
std::string BuildSystemSnapshotManifest(const std::string& requestId,
                                        const std::string& ruleId,
                                        const std::string& severity,
                                        const std::string& action,
                                        const std::string& snapshotPath,
                                        const std::string& treePath,
                                        const std::string& alertPath,
                                        const std::string& evidencePath);

/* Write a snapshot report to a UTF-8 file path. Returns true on success. */
bool WriteSystemSnapshotFile(const std::string& path, std::string& error,
                             const SnapshotOptions& options = {});

/* Collect and print the system snapshot report. Returns 0 on success. */
int RunSystemSnapshot();

} // namespace edr

#endif /* EDR_SYSTEM_SNAPSHOT_H */