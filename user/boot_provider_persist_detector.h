/*
 * boot_provider_persist_detector.h - Boot-loaded provider DLL persistence
 * detector (T1547.003 Time Providers, T1547.012 Print Processors).
 *
 * Both techniques share one shape: a DLL is registered under a service's
 * provider subkey and is then loaded at boot inside that trusted service
 * (w32time, spoolsv), giving SYSTEM-level persistence without a Run key.
 * EDR-148 already covers the sibling Print Monitors key (T1547.010); this
 * detector covers the remaining two provider surfaces.
 *   - W32Time\TimeProviders\<name>\DllName write                   -> 90
 *   - Print\Environments\...\Print Processors\<name>\Driver write   -> 90
 *   - command-plane reg add into either provider subkey             -> 90
 *   - Add-PrinterDriver / AddPrintProcessor with a payload DLL      -> 80
 *   - w32tm /register of a non-inbox provider                       -> 75
 *
 * A DLL path outside System32 raises nothing extra on its own here: the
 * registration itself is the anomaly. Read-only enumeration (reg query,
 * w32tm /query, Get-PrinterDriver) stays silent.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_BOOT_PROVIDER_PERSIST_DETECTOR_H
#define EDR_BOOT_PROVIDER_PERSIST_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class BootProviderPersistDetector {
public:
    BootProviderPersistDetector(bool enabled, uint32_t minScore,
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

#endif /* EDR_BOOT_PROVIDER_PERSIST_DETECTOR_H */
