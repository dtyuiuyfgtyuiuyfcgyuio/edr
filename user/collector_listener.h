/*
 * collector_listener.h - TCP/UDP listening-port monitoring collector.
 *
 * Polls the listening TCP/UDP tables and emits NET_LISTENER events when a
 * port starts or stops listening. Detects backdoors and C2 listeners
 * (MITRE T1071.001).
 */
#ifndef EDR_COLLECTOR_LISTENER_H
#define EDR_COLLECTOR_LISTENER_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace edr {

class ICollector;

enum class ListenerTableDomain { Tcp4, Udp4, Tcp6, Udp6 };

/* IPv4 uses the first four network-order bytes. IPv6 uses all 16; scopeId is
 * part of its identity. Image attribution requires exact process creation
 * evidence captured while sampling. Removal reuses that saved context. */
struct ListenerCollectorEntry {
    std::array<uint8_t, 16> address{};
    uint32_t scopeId = 0;
    uint16_t localPort = 0;
    uint32_t pid = 0;
    std::string imagePath;
    uint64_t processStartTime100ns = 0;
};
struct ListenerCollectorSnapshot {
    bool complete = false;
    std::vector<ListenerCollectorEntry> listeners;
};

/* Independent per-domain budgets: one sizing call, <=4 data calls, <=16 MiB
 * at a time, <=100000 rows. Any exhaustion invalidates the whole domain. */
constexpr uint32_t kListenerTableMaxBytes = 16 * 1024 * 1024;
constexpr size_t kListenerTableMaxEntries = 100000;
constexpr size_t kListenerTableMaxDataCalls = 4;
constexpr size_t kListenerMaxImageBytes = 4096;
constexpr size_t kListenerRetainedMaxBytes = 16 * 1024 * 1024;
/* Conservative x64 entry/key/map-node charge, plus actual path bytes. Native
 * enrichment also charges a context-cache record and path per unique PID. */
constexpr size_t kListenerEntryChargeBytes = 256;

using ListenerCollectorQuery =
    std::function<ListenerCollectorSnapshot(ListenerTableDomain)>;
/* Mirrors GetExtended*Table: *bytes is capacity on entry and required/returned
 * size on exit; return Win32 status. A missing reader uses the native tables.
 * Test providers execute on the worker; exceptions model fatal worker failure. */
using ListenerTableReader =
    std::function<uint32_t(ListenerTableDomain, void*, uint32_t*)>;
ListenerCollectorSnapshot QueryListenerCollectorTable(
    ListenerTableDomain domain, ListenerTableReader reader = {});

ICollector* CreateListenerCollector(uint32_t pollMs);
ICollector* CreateListenerCollector(uint32_t pollMs, ListenerCollectorQuery query);

} // namespace edr

#endif /* EDR_COLLECTOR_LISTENER_H */
