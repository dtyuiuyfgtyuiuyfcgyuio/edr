/*
 * collector_share.h - SMB network share monitoring collector.
 *
 * Polls the local share list (NetShareEnum) and emits SHARE_CHANGE events
 * when shares are added, removed, or modified. Detects lateral movement
 * preparation / data staging via new shares (MITRE T1021.002).
 */
#ifndef EDR_COLLECTOR_SHARE_H
#define EDR_COLLECTOR_SHARE_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace edr {

class ICollector;

struct ShareCollectorEntry {
    std::string name;
    std::string path;
    std::string type;
    std::string remark;
};

/* Only complete snapshots may replace the previous baseline. */
struct ShareCollectorSnapshot {
    bool complete = false;
    std::vector<ShareCollectorEntry> shares;
};

using ShareCollectorQuery = std::function<ShareCollectorSnapshot()>;

/* Native NetShareEnum pagination and the test provider use this same reader.
 * status is ERROR_SUCCESS, ERROR_MORE_DATA, or a failed Win32/NetAPI code. */
struct ShareCollectorPage {
    uint32_t status = 1;
    uint32_t resumeHandle = 0;
    std::vector<ShareCollectorEntry> shares;
};
using ShareCollectorPageQuery =
    std::function<ShareCollectorPage(uint32_t resumeHandle)>;
ShareCollectorSnapshot ReadShareCollectorSnapshot(const ShareCollectorPageQuery& query);

ICollector* CreateShareCollector(uint32_t pollMs);
ICollector* CreateShareCollector(uint32_t pollMs, ShareCollectorQuery query);

} // namespace edr

#endif /* EDR_COLLECTOR_SHARE_H */
