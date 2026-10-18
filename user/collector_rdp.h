/*
 * collector_rdp.h - Terminal Services / RDP session collector.
 *
 * Subscribes to LocalSessionManager (21/23/24/25) and
 * RemoteConnectionManager (1149) records and emits RDP_SESSION events.
 * Optional durable replay uses separate per-filter bookmarks; it never enables
 * either Windows Event Log channel.
 */
#ifndef EDR_COLLECTOR_RDP_H
#define EDR_COLLECTOR_RDP_H

#include <cstdint>

namespace edr {

class ICollector;
struct EventLogReplayOptions;

ICollector* CreateRdpCollector(uint32_t queueCapacity, uint32_t workers,
                               uint32_t maxXmlBytes,
                               EventLogReplayOptions replay);

} // namespace edr

#endif /* EDR_COLLECTOR_RDP_H */
