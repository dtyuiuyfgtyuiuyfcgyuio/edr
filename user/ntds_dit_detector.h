/*
 * ntds_dit_detector.h - NTDS.dit extraction detector (T1003.003).
 *
 * Scores PROCESS_START command lines that reach for the Active Directory
 * database (NTDS.dit), which only ever legitimately lives on a domain
 * controller under Windows\NTDS:
 *   - Volume Shadow Copy pivot into \Windows\NTDS\ntds.dit (the
 *     vssadmin-shadow extraction path)                          -> 90
 *   - ntdsutil IFM media creation (activate instance ntds /
 *     ifm / create full)                                        -> 85
 *   - esentutl /y <ntds.dit> (Jet DB raw copy)                  -> 80
 *   - PowerShell Copy-Item / .ExtractToFile() of ntds.dit       -> 80
 *   - generic copy/archive tool touching ntds.dit
 *     (copy/xcopy/robocopy/7z/tar/wbadmin)                      -> 70
 *   - any other command line that references ntds.dit           -> 60
 *   - FILE_READ of ntds.dit by a non-Windows-directory process  -> 80
 *     (the directory service and SYSTEM components legitimately
 *     touch the database; other readers are extraction attempts)
 *
 * The detector is a single-event scorer with per-signal dedup.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_NTDS_DIT_DETECTOR_H
#define EDR_NTDS_DIT_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class NtdsDitDetector {
public:
    NtdsDitDetector(bool enabled, uint32_t minScore,
                    uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool AnalyzeCommand(const std::string& lower, Finding* out) const;
    bool AnalyzeFileAccess(const Event& event, Finding* out) const;
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

#endif /* EDR_NTDS_DIT_DETECTOR_H */
