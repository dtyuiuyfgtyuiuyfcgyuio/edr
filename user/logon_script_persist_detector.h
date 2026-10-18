/*
 * logon_script_persist_detector.h - Logon-script and Active Setup
 * persistence detector (T1037.001 Logon Script (Windows),
 * T1547.014 Active Setup).
 *
 * Two quiet per-user autostart slots that the common autorun UIs do not
 * surface, so they outlive a Run-key cleanup:
 *   - UserInitMprLogonScript value written                          -> 90
 *   - Active Setup\Installed Components\<guid>\StubPath written      -> 90
 *   - Group Policy Scripts\Logon|Logoff|Startup directory payload    -> 85
 *   - logon script pointed at a user-writable path (temp/appdata)    -> 80
 *   - Active Setup component registered with no payload token yet    -> 75
 *
 * Read-only enumeration (reg query, Get-ItemProperty, gpresult) stays
 * silent. Complements registry_persistence (Run/IFEO/Winlogon plane) and
 * shortcut_persist (Startup folder plane).
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_LOGON_SCRIPT_PERSIST_DETECTOR_H
#define EDR_LOGON_SCRIPT_PERSIST_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class LogonScriptPersistDetector {
public:
    LogonScriptPersistDetector(bool enabled, uint32_t minScore,
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

    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_LOGON_SCRIPT_PERSIST_DETECTOR_H */
