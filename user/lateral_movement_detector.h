/*
 * lateral_movement_detector.h - Lateral movement / internal host scanning detector.
 *
 * Correlates NET_CONNECT events per attribution key into a rolling window.
 * When at least minDestCount distinct destination IPs are connected to on
 * any of the watched lateral-movement ports within the window, the current
 * event is stamped with:
 *   lateral_move_score         = min(100, destCount * scorePerDest)
 *   lateral_move_dest_count    = number of distinct destination IPs
 *   lateral_move_ports         = comma-separated matched port numbers seen
 *   lateral_move_window_seconds
 *
 * Watched ports (ATT&CK T1021):
 *   SMB        445
 *   RDP        3389
 *   WinRM      5985, 5986
 *   RPC/DCE    135
 *   NetBIOS    139
 *   SSH        22
 *   Telnet     23
 *   VNC        5900
 *
 * Attribution: events with a pid and image are keyed as
 * "pid:<pid>@<image basename>"; events with an image but no pid fall back to
 * "img:<image basename>"; events with neither are skipped. Loopback
 * destinations (127.*) are excluded.
 *
 * State is a bounded time-expiring LRU; expired keys are swept lazily on
 * every Enrich call. The flag resets when the key expires, so detection can
 * re-fire after a quiet period.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_LATERAL_MOVEMENT_DETECTOR_H
#define EDR_LATERAL_MOVEMENT_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class LateralMovementDetector {
public:
    LateralMovementDetector(bool enabled, uint32_t windowSeconds,
                            size_t stateCapacity, uint32_t minDestCount,
                            uint32_t scorePerDest);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects. */
    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_keys.size(); }

private:
    struct KeyState {
        std::set<std::string> destIps;
        std::set<std::string> ports;
        bool flagged = false;
        uint64_t lastSeen100ns = 0;
    };

    void PurgeExpired(uint64_t now100ns);
    void WriteState(Event& event, const KeyState& state);
    static bool IsLateralPort(const std::string& portStr, std::string& portOut);
    static bool IsLoopback(const std::string& ip);

    bool     m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t   m_stateCapacity;
    uint32_t m_minDestCount;
    uint32_t m_scorePerDest;
    std::unordered_map<std::string, KeyState> m_keys;
};

} // namespace edr

#endif /* EDR_LATERAL_MOVEMENT_DETECTOR_H */
