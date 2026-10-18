/*
 * disk_wipe_detector.h - Destructive disk-wipe detector (T1485/T1561).
 *
 * Ransomware and destructive operators destroy data at the disk layer
 * after suppressing backups (shadow copies are covered by shadow_copy).
 * This detector scores PROCESS_START command lines for disk destruction:
 *   - diskpart clean all (full device erase)                        -> 90
 *   - diskpart clean (partition wipe)                                -> 85
 *   - format <drive> full format                                     -> 85
 *   - format <drive> /q quick format                                 -> 75
 *   - PowerShell Format-Volume / Clear-Volume                        -> 70
 *   - cipher /w:<dir> free-space wipe (destroys deleted-file remnants) -> 60
 *
 * Alerts are deduplicated per signal key inside the dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_DISK_WIPE_DETECTOR_H
#define EDR_DISK_WIPE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class DiskWipeDetector {
public:
    DiskWipeDetector(bool enabled, uint32_t minScore,
                     uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        std::string target;
    };

    bool AnalyzeCommandLine(const std::string& lower, Finding* out) const;
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

#endif /* EDR_DISK_WIPE_DETECTOR_H */
