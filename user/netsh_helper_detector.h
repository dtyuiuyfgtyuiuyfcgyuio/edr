/*
 * netsh_helper_detector.h - Netsh helper-DLL persistence detector
 * (T1546.007).
 *
 * Scores installation of arbitrary DLLs into netsh.exe:
 *   - netsh add helper <dll>                                      -> 90
 *   - REG_WRITE under HKLM\SOFTWARE\Microsoft\NetSh               -> 85
 *   - PowerShell wrapping netsh add helper                        -> 90
 *
 * Read-only `netsh show helper` / `netsh interface show` stay silent.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_NETSH_HELPER_DETECTOR_H
#define EDR_NETSH_HELPER_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class NetshHelperDetector {
public:
    NetshHelperDetector(bool enabled, uint32_t minScore,
                        uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& lower, bool registryPlane,
                 Finding* out) const;
    void Stamp(Event& event, const Finding& finding,
               const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_NETSH_HELPER_DETECTOR_H */
