/*
 * svc_recovery_detector.h - Service recovery action hijack detector
 * (T1037.004 / T1543.003 recovery plane, formerly T1037).
 *
 * A service's FailureActions / FailureCommand defines what Windows
 * executes when the service crashes. Re-pointing it at an interpreter
 * or a user-writable binary turns a privileged service into a
 * persistence/privilege-escalation trampoline that fires on the next
 * crash — no ImagePath or ServiceDll change required.
 *
 * Scores the payload that will be executed on failure:
 *   - command contains an interpreter (powershell/pwsh/cmd/wscript/
 *     cscript/rundll32/mshta/regsvr32)                         -> 90
 *   - command points into a user-writable directory (Temp/
 *     AppData/Public/ProgramData/Downloads/Desktop)             -> 90
 *   - command is a non-system .exe outside \windows\system32\  -> 85
 *   - command is an .exe/.bat/.ps1 outside system32 (generic)  -> 85
 *   - FailureActions binary value written with no token parsed  -> 75
 *
 * Read-only queries (sc qfailure / reg query / Get-ItemProperty),
 * msiexec/TrustedInstaller writes and payloads that stay inside
 * \windows\system32\ stay silent. Complements svc_path_abuse
 * (ImagePath plane) and service_dll_hijack (ServiceDll plane).
 *
 * Dual REG_WRITE shape handled (bare key + value NAME vs full key +
 * DATA). Command plane watches "sc failure" / "sc.exe failure" and
 * PowerShell's Set-Service -FailureAction / New-Service forms.
 *
 * Thread-safety: single EventBus consumer thread only.
 */
#ifndef EDR_SVC_RECOVERY_DETECTOR_H
#define EDR_SVC_RECOVERY_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class SvcRecoveryDetector {
public:
    SvcRecoveryDetector(bool enabled, uint32_t minScore,
                        uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_state.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    static bool ClassifyPayload(const std::string& data, Finding* out);

    void Stamp(Event& event, const Finding& finding, const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_capacity;
    std::unordered_map<std::string, uint64_t> m_state;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_SVC_RECOVERY_DETECTOR_H */
