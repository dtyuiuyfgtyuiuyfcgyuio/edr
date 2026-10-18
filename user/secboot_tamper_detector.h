/*
 * secboot_tamper_detector.h - Security-boot stack tampering detector
 * (VBS / HVCI / Credential Guard disable; T1562.001).
 *
 * Scores command lines, PowerShell script bodies, and REG_WRITE events
 * that weaken the virtualization-based security stack:
 *   - EnableVirtualizationBasedSecurity = 0                     -> 85
 *   - HypervisorEnforcedCodeIntegrity (HVCI) Enabled = 0        -> 85
 *   - LsaCfgFlags = 0 (Credential Guard disable)                -> 80
 *   - RequirePlatformSecurityFeatures weakened to 1             -> 75
 *   - reg add / Set-ItemProperty command-plane variants         -> 75
 *
 * REG_WRITE dual shapes are both matched (see workspace contract):
 * driver/imonitor shape carries the bare value name in kRegValue,
 * sysmon/snapshot shapes carry the data in kRegValue and the full path
 * including the value name as the last component of kRegKey. A write
 * carrying explicit nonzero data never fires (legit hardening).
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_SECBOOT_TAMPER_DETECTOR_H
#define EDR_SECBOOT_TAMPER_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class SecbootTamperDetector {
public:
    SecbootTamperDetector(bool enabled, uint32_t minScore,
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

    /* Text plane (command line / script body). */
    bool AnalyzeText(const std::string& lower, Finding* out) const;
    /* Registry-write plane (dual shape). */
    bool AnalyzeRegistry(const Event& event, Finding* out) const;
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

#endif /* EDR_SECBOOT_TAMPER_DETECTOR_H */
