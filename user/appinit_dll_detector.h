/*
 * appinit_dll_detector.h - AppInit_DLLs / AppCertDlls persistence
 * detector (T1546.010 / T1546.009).
 *
 * Scores registry and command-plane planting of boot-time injected
 * DLLs:
 *   - REG_WRITE / reg add AppInit_DLLs with a payload             -> 90
 *   - REG_WRITE / reg add AppCertDlls                             -> 90
 *   - LoadAppInit_DLLs enabled (=1)                               -> 80
 *   - RequireSignedAppInit_DLLs disabled (=0)                     -> 70
 *
 * Empty-value cleanup and read-only queries stay silent. Complements
 * persistence_chain / registry_persistence, which only tag the key as
 * a chain mechanism.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_APPINIT_DLL_DETECTOR_H
#define EDR_APPINIT_DLL_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class AppinitDllDetector {
public:
    AppinitDllDetector(bool enabled, uint32_t minScore,
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

#endif /* EDR_APPINIT_DLL_DETECTOR_H */
