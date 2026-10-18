/*
 * screensaver_persist_detector.h - Screensaver hijack persistence
 * detector (T1546.002 Event Triggered Execution: Screensaver, formerly
 * T1180).
 *
 * SCRNSAVE.EXE under HKCU\Control Panel\Desktop launches whatever
 * binary it names whenever the interactive session goes idle, with no
 * Run-key or Startup-folder footprint:
 *   - value data naming an interpreter (powershell/cmd/wscript/
 *     rundll32/mshta)                                          -> 90
 *   - value data in a user-writable location (Temp/AppData/
 *     Public/ProgramData/Downloads/Desktop)                     -> 90
 *   - value data with any other payload extension (.exe/.scr/
 *     .bat/.ps1/...) outside those locations                    -> 85
 *   - the slot registered with no data observed (driver shape
 *     carries the value NAME only)                              -> 75
 *   - a .scr under \windows\system32\ (stock screensavers) and
 *     read-only queries (reg query / Get-ItemProperty) stay silent
 *
 * Honors the REG_WRITE dual shape: driver/imonitor events carry the
 * bare key plus the value NAME, sysmon/reg_watch snapshots carry the
 * full key including the value name plus the DATA. Complements
 * registry_persistence (Run/IFEO/Winlogon plane) and logon_script
 * (UserInit/Active Setup plane).
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_SCREENSAVER_PERSIST_DETECTOR_H
#define EDR_SCREENSAVER_PERSIST_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ScreensaverPersistDetector {
public:
    ScreensaverPersistDetector(bool enabled, uint32_t minScore,
                               uint32_t dedupWindowSeconds,
                               size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    /* Grades the payload DATA assigned to SCRNSAVE.EXE. Returns false
     * when the data names nothing worth alerting on. */
    static bool ClassifyPayload(const std::string& data, Finding* out);

    /* Extracts the data assigned after /d (reg add) or -Value
     * (Set-ItemProperty) following a SCRNSAVE.EXE mention. The marker
     * scan runs on the lowercased copy while the slice comes from raw
     * (identical byte length). */
    static bool ExtractAssignedData(const std::string& raw,
                                    const std::string& lower,
                                    std::string* out);

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

#endif /* EDR_SCREENSAVER_PERSIST_DETECTOR_H */
