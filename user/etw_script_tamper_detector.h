/*
 * etw_script_tamper_detector.h - Script-plane ETW impairment detector
 * (T1562.001, the command/script-face complement to the runtime plane:
 * collector_etw_tamper observes live provider/session/patch state and
 * ApiHookDetector observes inline hooks; this detector scores the act of
 * ordering telemetry stripped from inside a script or one-liner):
 *
 *   - PSEtwLogProvider reflection strip                        -> 85
 *   - EtwEventWrite patch pair (VirtualProtect / WriteProcessMemory /
 *     Copy) in script context                                   -> 90
 *   - bare EtwEventWrite reference (write-up / tooling excerpt) -> 60
 *   - trace-session stop cmdlets (Stop-/Remove-EtwTraceSession,
 *     Set-EtwTrafficPolicy)                                     -> 80
 *   - logman stop/delete naming a telemetry session             -> 75
 *   - ETW Autologger start-key disable                          -> 70
 *   - wevtutil channel disable (/e:false)                       -> 70
 *
 * Face selection follows the house contract: kCommandLine first, then
 * kScriptBlockText for POWERSHELL_SCRIPT events (the body lives only
 * there), then kImage as fallback.
 *
 * Alerts are deduplicated per normalized text prefix inside the dedup
 * window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_ETW_SCRIPT_TAMPER_DETECTOR_H
#define EDR_ETW_SCRIPT_TAMPER_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class EtwScriptTamperDetector {
public:
    EtwScriptTamperDetector(bool enabled, uint32_t minScore,
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

#endif /* EDR_ETW_SCRIPT_TAMPER_DETECTOR_H */
