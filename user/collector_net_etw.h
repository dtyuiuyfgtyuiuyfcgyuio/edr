#ifndef EDR_COLLECTOR_NET_ETW_H
#define EDR_COLLECTOR_NET_ETW_H
#include <cstdint>
#include <string>
namespace edr {
struct NetConnectInfo {
    uint32_t pid = 0;
    uint32_t daddr[4] = {0,0,0,0}; /* network byte order (IPv4 in daddr[0]) */
    uint32_t saddr[4] = {0,0,0,0};
    uint16_t dport = 0; /* network byte order */
    uint16_t sport = 0; /* network byte order */
    bool ipv6 = false;
    bool udp = false;
};
bool IsNetEtwKeepEvent(uint16_t eventId, bool udpEnabled);
bool ParseNetConnectPayload(uint16_t eventId, const uint8_t* payload, uint32_t byteCount, NetConnectInfo& out);
std::string NetIpToString(bool ipv6, const uint32_t addr[4]);
class ICollector;
ICollector* CreateNetEtwCollector(bool udpEnabled);
}
#endif
