/*
 * wmi_exec_detector.h - Windows Management Instrumentation / CIM execution
 * detection (T1047).
 *
 * ---------------------------------------------------------------------------
 * COVERED BY THIS MODULE (WMI/CIM *execution* surface only):
 *   - wmic process call create / wmic process create   (local WMI process launch)
 *   - wmic /node:<host> remote execution, including explicit credentials
 *     (-u / -p, /user: / /password:)
 *   - PowerShell Invoke-CimMethod / Invoke-WmiMethod -MethodName Create
 *   - PowerShell Get-WmiObject / Get-CimInstance Win32_Process + .Create(
 *   - Win32_ProcessStartup hidden-window evasion (ShowWindow / CreateFlags)
 *   - wmic executed from a non-system32 (user-writable / temp) path, or a
 *     typosquatted wmic image name (形近, e.g. wm1c.exe)
 *
 * EXPLICITLY NOT COVERED (owned by other detectors; never matched here):
 *   - WMI event-subscription persistence (__EventFilter / CommandLineEventConsumer
 *     / FilterToConsumerBinding)                  -> wmi_persistence / persist_burst
 *   - pure WMI query recon (Get-WmiObject Win32_ComputerSystem with no Create)
 *                                                      -> discovery_recon
 *   - WMI collector instrumentation                          -> collector_wmi
 *   - lateral authentication                                 -> lateral_movement
 *   - bare "wmic.exe + process call create" command-line regex (EDR-144 / EDR-268)
 *     are KEPT AS-IS. This module adds the PowerShell CIM surface, the remote
 *     /node: surface, and aggregate scoring on top of those two rules; it does
 *     NOT re-implement their matching.
 *
 * SCORING (house rule, CONTRACT §3.4):
 *   score >= 75 -> verdict "malicious"  + score/verdict/signals/techniques
 *   55..74      -> verdict "suspicious" + score/verdict/signals/techniques
 *   < 55        -> fully silent (no fields written)
 *   Additionally, if score < cfg.minScore -> silent.
 *
 * PER-SIGNAL BASE SCORES (max base wins; +5 corroboration bonus when at least
 * two signals co-occur and one is lower-confidence (<75), capped at 100):
 *   wmic_process_call_create      75  (malicious)  local/remote process launch
 *   ps_invoke_create             75  (malicious)  Invoke-CimMethod/Invoke-WmiMethod -MethodName Create
 *   ps_getwin32_create           75  (malicious)  Get-WmiObject/Get-CimInstance Win32_Process + .Create(
 *   win32_processstartup_hidden  75  (malicious)  Win32_ProcessStartup ShowWindow/CreateFlags evasion
 *   wmic_remote_creds            74  (suspicious) /node: remote + explicit creds
 *   wmic_node_remote             55  (suspicious) /node: remote execution (no creds)
 *   wmic_nonsystem32             55  (suspicious) wmic image outside system32\wbem
 *   wmic_relative_name           54  (silent)     typosquatted wmic name (low confidence)
 *
 * TEXT EXTRACTION ORDER (house rule, trap #1): kCommandLine ->
 * (EDR_EVT_POWERSHELL_SCRIPT: kScriptBlockText) -> kImage fallback. This module
 * inspects ONLY PROCESS_START(1) and WMI_EVENT(13); POWERSHELL_SCRIPT bodies are
 * consulted only when that type is inspected (it is not), so PowerShell WMI-exec
 * content is reached via the powershell.exe command line on PROCESS_START.
 *
 * THREAD-SAFETY: no internal synchronization; only the single EventBus consumer
 * thread calls Enrich (see main.cpp).
 */
#ifndef EDR_WMI_EXEC_DETECTOR_H
#define EDR_WMI_EXEC_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class WmiExecDetector {
public:
    WmiExecDetector(bool enabled, uint32_t minScore,
                    uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        std::string signals;
        std::string techniques;
    };

    bool Analyze(const std::string& text, const std::string& lower,
                 const std::string& image, const std::string& imageLower,
                 Finding* out) const;

    void Stamp(Event& event, const Finding& finding, const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_WMI_EXEC_DETECTOR_H */
