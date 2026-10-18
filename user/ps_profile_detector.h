/*
 * ps_profile_detector.h - PowerShell profile persistence detector
 * (T1546.013 Event Triggered Execution: PowerShell Profile).
 *
 * PowerShell profiles execute automatically on every interpreter start, so
 * staging a payload into $PROFILE turns any later powershell.exe launch
 * (including WMI/persistence-driven ones) into code execution. Two surfaces:
 *   - Command / script surface (PROCESS_START command line, PS_SCRIPT body):
 *     $PROFILE or *.ps1 profile file references combined with write verbs
 *     (Set-Content / Add-Content / Out-File / New-Item / redirect) and
 *     optional payload markers (download cradles, -enc, iex).
 *   - File surface (FILE_CREATE / FILE_RENAME): profile-named files dropped
 *     inside WindowsPowerShell / PowerShell 7 profile directories, or staged
 *     elsewhere (Temp / Downloads) before placement.
 * Scoring:
 *   95  profile write + download/payload markers (cradle staged into profile)
 *   90  AllUsers ($PSHOME / Program Files) profile write or file placement
 *   85  CurrentUser profile write, or profile file placed in profile dir
 *   75  profile-named file created outside a profile directory (staging)
 *   60  profile referenced with payload marker but no write verb (recon)
 * Read-only references (Get-Content / Test-Path / dot-sourcing execution,
 * notepad/ise) and the about_Profiles help topic stay silent.
 */
#ifndef EDR_PS_PROFILE_DETECTOR_H
#define EDR_PS_PROFILE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PsProfileDetector {
public:
    PsProfileDetector(bool enabled, uint32_t minScore,
                      uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects; lets the caller skip the
     * copy/enrich pipeline for unrelated types. */
    static bool Inspects(uint16_t type);

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };
    bool AnalyzeText(const std::string& lower, Finding* out) const;
    bool AnalyzeFile(const std::string& lowerPath, Finding* out) const;
    void Stamp(Event& event, const Finding& finding, const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;
    std::unordered_map<std::string, uint64_t> m_lastAlert;
    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_PS_PROFILE_DETECTOR_H */
