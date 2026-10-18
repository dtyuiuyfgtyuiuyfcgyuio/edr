/*
 * downgrade_attack_detector.h - Version downgrade / logging-evasion
 * detector (T1562.010 Downgrade Attack).
 *
 * Scores deliberate downgrades to older protocol or runtime versions that
 * lack modern telemetry and hardening:
 *   - powershell -version 2 (no ScriptBlock logging, no AMSI)      -> 90
 *   - SMBv1 re-enabled (Set-SmbServerConfiguration / dism /
 *     registry SMB1=1)                                            -> 85
 *   - .NET legacy v2 runtime activation policy                     -> 75
 *   - SSL 3.0 / TLS 1.0 re-enabled in the SCHANNEL protocol keys    -> 70
 *
 * `-ExecutionPolicy Bypass` alone is far too common to score and is left
 * to the PowerShell rules. Read-only queries stay silent.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_DOWNGRADE_ATTACK_DETECTOR_H
#define EDR_DOWNGRADE_ATTACK_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class DowngradeAttackDetector {
public:
    DowngradeAttackDetector(bool enabled, uint32_t minScore,
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

#endif /* EDR_DOWNGRADE_ATTACK_DETECTOR_H */
