/*
 * tunnel_tool_detector.h - Tunneling / port-forwarding tool detector
 * (MITRE T1572 Protocol Tunneling, T1090 Proxy).
 *
 * Inspects EDR_EVT_PROCESS_START events for tools commonly used to
 * establish covert tunnels and reverse port forwards out of the network:
 *  - ssh with -R/-L/-D forward flags
 *  - plink (PuTTY link) with -R/-L flags
 *  - ncat / nc / socat listeners with relay/exec chaining
 *  - ngrok and other packaged tunnel clients (chisel, frpc, stowaway,
 *    ligolo, rinetd)
 *  - netsh interface portproxy rules (T1090.001 built-in port proxy)
 * Events are stamped with tunnel_* fields when a signal is found.
 * The detector is stateless: every interesting PROCESS_START is scored
 * immediately.
 */
#ifndef EDR_TUNNEL_TOOL_DETECTOR_H
#define EDR_TUNNEL_TOOL_DETECTOR_H

#include <cstdint>
#include <string>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

struct TunnelToolSignal {
    bool suspicious = false;
    uint32_t score = 0;
    std::string signals;  /* comma-separated signal names */
    std::string tools;    /* comma-separated tool names */
    std::string verdict;
};

/* Pure classification helper, exposed for unit tests. */
TunnelToolSignal ClassifyTunnelCommand(const std::string& image,
                                       const std::string& commandLine);

class TunnelToolDetector {
public:
    explicit TunnelToolDetector(bool enabled);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

private:
    bool m_enabled;
};

} // namespace edr

#endif /* EDR_TUNNEL_TOOL_DETECTOR_H */
