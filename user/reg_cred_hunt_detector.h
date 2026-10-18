/*
 * reg_cred_hunt_detector.h - Credentials-in-registry hunting detector
 * (T1552.002 Credentials in Registry).
 *
 * Complements cred_file_hunt (filesystem plane) with the registry plane:
 *   - reg query with a password/credential search string across a hive
 *     (reg query HKLM /f password /t REG_SZ /s)                   -> 90
 *   - Winlogon autologon secrets read (DefaultPassword,
 *     AltDefaultPassword)                                          -> 85
 *   - third-party credential stores read: PuTTY sessions, WinSCP,
 *     TightVNC/RealVNC password values, SNMP community strings      -> 80
 *   - PowerShell recursive registry search for a credential pattern -> 85
 *   - broad Get-ItemProperty sweep of an autologon key              -> 70
 *
 * Writing an autologon password is a configuration action rather than
 * credential theft and is left to the persistence detectors; only reads
 * and searches score here. Enumerating a key without a credential
 * selector stays silent.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_REG_CRED_HUNT_DETECTOR_H
#define EDR_REG_CRED_HUNT_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class RegCredHuntDetector {
public:
    RegCredHuntDetector(bool enabled, uint32_t minScore,
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

#endif /* EDR_REG_CRED_HUNT_DETECTOR_H */
