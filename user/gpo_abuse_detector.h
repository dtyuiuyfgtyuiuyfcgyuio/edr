/*
 * gpo_abuse_detector.h - Group Policy modification detector
 * (T1484.001).
 *
 * Scores domain/local policy tampering that attackers use to persist
 * or deploy payloads across an OU:
 *   - SharpGPOAbuse / PowerGPOAbuse tooling                       -> 90
 *   - registry.pol / gpt.ini / scripts.ini staged into SYSVOL     -> 85
 *   - New-GPO / Set-GPRegistryValue / New-GPLink / Set-GPPermission
 *                                                                 -> 80
 *   - lgpo.exe import / parse of a .pol                           -> 80
 *   - secedit /configure                                          -> 75
 *   - REG_WRITE under Group Policy / Policies\...\Scripts         -> 75
 *
 * Read-only gpresult / Get-GPO / gpupdate stay silent.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_GPO_ABUSE_DETECTOR_H
#define EDR_GPO_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class GpoAbuseDetector {
public:
    GpoAbuseDetector(bool enabled, uint32_t minScore,
                     uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& lower, Finding* out) const;
    bool AnalyzeReg(const std::string& lowerKeyValue, Finding* out) const;
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

#endif /* EDR_GPO_ABUSE_DETECTOR_H */
