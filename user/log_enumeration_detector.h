/*
 * log_enumeration_detector.h - Event log enumeration detector (T1654).
 *
 * Before clearing or disabling auditing, an operator enumerates what is
 * actually being recorded: which channels exist, which are enabled, and
 * what the retention / size configuration is. This detector scores the
 * command / script plane that performs that read:
 *
 *   Command plane (EDR_EVT_PROCESS_START) and PowerShell plane
 *   (EDR_EVT_POWERSHELL_SCRIPT, body ONLY in kScriptBlockText). Text
 *   order: kCommandLine -> (PS_SCRIPT) kScriptBlockText -> kImage.
 *
 * Tiers:
 *   75 security_log_targeting  an enumeration or log-config query that
 *                              names a security-relevant channel
 *                              (Security, Sysmon, Defender, PowerShell,
 *                              WinRM, Terminal Services, AppLocker, Code
 *                              Integrity, SMBClient, WDAC). Asking
 *                              specifically about the defensive channels
 *                              is the sizing step before tampering with
 *                              them.
 *   65 event_log_enumeration   bulk enumeration of the log inventory:
 *                              `wevtutil el`, `Get-WinEvent -ListLog ...`,
 *                              `Get-EventLog -List`.
 *   60 log_config_query        per-log configuration read that does not
 *                              name a defensive channel: `wevtutil gl`,
 *                              `Get-WinEvent -ListProvider`.
 *
 * Deliberate silences - this detector owns the DISCOVERY face only:
 *   - `wevtutil clear-log` / `cl` / `sl` (clearing, disabling or
 *     reconfiguring a log) is a TAMPER action owned by
 *     EventlogTamperDetector (T1070.001 / T1562.002) and
 *     DefenseEvasionDetector (audit_log_tamper), and stays silent here;
 *   - `wevtutil qe` (query-events, i.e. reading recorded events) is
 *     content reading, not inventory enumeration, and stays silent;
 *   - the needles carry their subcommand ("wevtutil el", "wevtutil gl"),
 *     so a clear-log invocation can never match them.
 *
 * Verdict contract: >=75 MALICIOUS, >=55 SUSPICIOUS, below 55 never
 * stamped (the min_score gate runs first; a sub-55 finding early-exits).
 *
 * Dedup: key is the signal (tier) name. The same tier inside the dedup
 * window is suppressed; window expiry or a different tier re-arms.
 * State capacity overflow clears the dedup map (same policy as
 * netprovider_persist_detector).
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_LOG_ENUMERATION_DETECTOR_H
#define EDR_LOG_ENUMERATION_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class LogEnumerationDetector {
public:
    LogEnumerationDetector(bool enabled, uint32_t minScore,
                           uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        std::string tool;
        std::string channel;
    };

    bool AnalyzeCommandText(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key (signal) -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_LOG_ENUMERATION_DETECTOR_H */
