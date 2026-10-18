/*
 * winrm_config_tamper_detector.h - WinRM configuration enablement /
 * trust-broadening detector (T1021.006 preparation plane).
 *
 * Complements winrm_abuse_detector (which scores remote execution):
 * this detector scores configuration changes that ENABLE or widen
 * WinRM reach before lateral movement:
 *   - Set-Item WSMan:...Client\TrustedHosts (any value)          -> 80
 *   - winrm set winrm/config/client @{TrustedHosts="*"}           -> 80
 *   - TrustedHosts wildcard ("*") or broad list value             -> 85
 *   - Enable-PSRemoting -Force                                    -> 75
 *   - winrm quickconfig (-q / -force)                             -> 65
 *
 * Read-only `winrm identify` / `winrm get winrm/config` stays silent.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_WINRM_CONFIG_TAMPER_DETECTOR_H
#define EDR_WINRM_CONFIG_TAMPER_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class WinrmConfigTamperDetector {
public:
    WinrmConfigTamperDetector(bool enabled, uint32_t minScore,
                              uint32_t dedupWindowSeconds,
                              size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding,
               const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_WINRM_CONFIG_TAMPER_DETECTOR_H */
