/*
 * registry_hive_detector.h - Sensitive registry hive copy / export detector
 * (T1003.002 SAM, T1003.004 LSA Secrets).
 *
 * Scores PROCESS_START command lines and POWERSHELL_SCRIPT bodies that
 * reach for the SAM / SECURITY / SYSTEM hives:
 *   - reg save of a hive root into a public / desktop / UNC staging
 *     location                                              -> 90
 *   - reg save of a hive root elsewhere                     -> 85
 *   - esentutl against the live hive file
 *     (\windows\system32\config\sam ...)                    -> 85
 *   - copy-tool verbs against the live hive file, staged    -> 90
 *   - copy-tool verbs against the live hive file            -> 85
 *   - reg export of a hive root                             -> 70 (75 staged)
 *
 * Subkey paths (hklm\system\currentcontrolset\...) are deliberately not
 * hive-root references; temp output is not staging.
 *
 * Alerts are deduplicated per normalized command prefix inside the
 * dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_REGISTRY_HIVE_DETECTOR_H
#define EDR_REGISTRY_HIVE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class HiveCopyDetector {
public:
    HiveCopyDetector(bool enabled, uint32_t minScore,
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

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_REGISTRY_HIVE_DETECTOR_H */