/*
 * cmstp_bypass_detector.h - CMSTP / INF proxy execution detector
 * (T1218.003 CMSTP, T1216.001 Control Panel, T1127 indirect INF).
 *
 * CMSTP can proxy arbitrary inf InstallHinfSection execution with
 * elevated context, and attackers routinely host remote INF via http.
 * Scoring:
 *   - cmstp with remote INF (http/https/\\unc)               -> 90
 *   - cmstp with INF in user-writable path (Temp/AppData)   -> 90
 *   - cmstp with INF in other local path                     -> 85
 *   - bare cmstp without INF but with /ni or /s              -> 75
 *   - control.exe with .cpl in writable path                 -> 75
 *
 * Complements dev_util_proxy (MSBuild/csc) and indirect_exec
 * (forfiles/pcalua/ieexec) which do not cover cmstp.
 */
#ifndef EDR_CMSTP_BYPASS_DETECTOR_H
#define EDR_CMSTP_BYPASS_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class CmstpBypassDetector {
public:
    CmstpBypassDetector(bool enabled, uint32_t minScore,
                        uint32_t dedupWindowSeconds, size_t stateCapacity);
    void Enrich(Event& event);
    static bool Inspects(uint16_t type);
private:
    struct Finding { uint32_t score = 0; const char* signal = ""; };
    bool Analyze(const std::string& lower, const std::string& raw, Finding* out) const;
    void Stamp(Event& event, const Finding& finding, const std::string& key);
    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;
    std::unordered_map<std::string, uint64_t> m_lastAlert;
    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif
