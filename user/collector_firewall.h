/*
 * collector_firewall.h - Windows Firewall rule monitoring collector.
 *
 * Polls the firewall rule registry store and emits FIREWALL_RULE events
 * when rules are added, removed, or modified. Detects firewall policy
 * tampering / disabling defenses (MITRE T1562.004).
 */
#ifndef EDR_COLLECTOR_FIREWALL_H
#define EDR_COLLECTOR_FIREWALL_H

#include <windows.h>

#include <cstdint>
#include <cstddef>
#include <functional>
#include <map>
#include <string>

namespace edr {

class ICollector;

enum class FirewallSnapshotStatus { Complete, Missing, Failed };

struct FirewallCollectorSnapshot {
    FirewallSnapshotStatus status = FirewallSnapshotStatus::Failed;
    std::map<std::string, std::string> values;
};

struct FirewallSnapshotLimits {
    size_t maxEnumeratedValues = 8192;
    size_t maxValues = 4096;
    size_t maxNameBytes = 1024;
    size_t maxValueBytes = 32 * 1024;
    size_t maxTotalPayloadBytes = 4 * 1024 * 1024;
};

using FirewallCollectorQuery = std::function<FirewallCollectorSnapshot()>;
using FirewallSnapshotReadHook =
    std::function<void(size_t attempt, size_t valuesRead)>;

/* Reads one registry key without exposing partial snapshots. */
FirewallCollectorSnapshot ReadFirewallRegistrySnapshot(
    HKEY key, const FirewallSnapshotLimits& limits = {},
    FirewallSnapshotReadHook afterValueRead = {});

ICollector* CreateFirewallCollector(uint32_t pollMs);
ICollector* CreateFirewallCollector(uint32_t pollMs, FirewallCollectorQuery query);

} // namespace edr

#endif /* EDR_COLLECTOR_FIREWALL_H */
