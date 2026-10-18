/*
 * password_cracking_detector.h - Offline password-cracking detector
 * (T1110.002).
 *
 * After credential harvesting (LSASS/SAM/NTDS.dit), attackers crack the
 * offline hashes. This detector scores PROCESS_START events for cracking
 * tooling identified by image name and distinctive command-line tokens:
 *   - hashcat                          -> 90
 *   - John the Ripper (john.exe)       -> 85
 *   - ophcrack (rainbow tables)        -> 80
 *   - samdump2 (SAM hash extraction)   -> 75
 *   - Cain & Abel (cain.exe)           -> 75
 *   - fcrackzip                        -> 60
 *   - hashid / hash-identifier         -> 55
 *
 * Matching is word/name aware: "john" only matches the john.exe image
 * basename, never a file or user named john.
 *
 * Alerts are deduplicated per signal key inside the dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_PASSWORD_CRACKING_DETECTOR_H
#define EDR_PASSWORD_CRACKING_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PasswordCrackingDetector {
public:
    PasswordCrackingDetector(bool enabled, uint32_t minScore,
                             uint32_t dedupWindowSeconds,
                             size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        std::string tool;
    };

    bool Analyze(const std::string& lowerBase,
                 const std::string& lowerCmd, Finding* out) const;
    void Stamp(Event& event, const Finding& finding);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_PASSWORD_CRACKING_DETECTOR_H */
