/*
 * lsass_dump_detector.h - One-liner LSASS memory dump detector (T1003.001).
 *
 * Scores PROCESS_START command lines that dump LSASS via well-known
 * one-liners - the command-plane complement to CredentialDumpingDetector
 * (which covers lsass.exe handle access, hive reads and named pipes):
 *   - rundll32 comsvcs.dll,#MiniDump <pid> <out.dmp> full      -> 90
 *   - procdump/procump/rundll32 keyed on an lsass target       -> 85
 *   - mimikatz / nanodump / secretsdump / hashdump /
 *     pypykatz / lsassy command tokens                         -> 90
 *   - Task Manager-like "Create dump file" via
 *     Get-Process lsass | ... or .Dump()                       -> 80
 *
 * A command is only scored when both a dumper and an LSASS indicator
 * are present, except for the unambiguous tool tokens (mimikatz et al.)
 * which score alone.
 *
 * Alerts are deduplicated per normalized command prefix inside the
 * dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_LSASS_DUMP_DETECTOR_H
#define EDR_LSASS_DUMP_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class LsassDumpDetector {
public:
    LsassDumpDetector(bool enabled, uint32_t minScore,
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
    void Stamp(Event& event, const Finding& finding, const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_LSASS_DUMP_DETECTOR_H */
