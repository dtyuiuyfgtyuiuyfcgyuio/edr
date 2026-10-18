/*
 * reg_modify_detector.h - Modify Registry: security-control plane
 * downgrade / tamper (T1112).
 *
 * COVERAGE (this module)
 *   Tampering with the host's security-control registry surface:
 *     - UAC policy   (Policies\System):
 *         EnableLUA=0, ConsentPromptBehaviorAdmin=0,
 *         PromptOnSecureDesktop=0, FilterAdministratorToken=0,
 *         LocalAccountTokenFilterPolicy=1
 *     - LSA / auth policy (Control\Lsa):
 *         LmCompatibilityLevel<3, NoLMHash=0, RunAsPPL=0,
 *         LimitBlankPasswordUse=0, RestrictAnonymous=0,
 *         DisableDomainCreds=1
 *     - SMB signing off (LanmanServer\Parameters):
 *         RequireSecuritySignature=0
 *     - Machine-level PowerShell execution policy:
 *         ExecutionPolicy = Bypass | Unrestricted  (HKLM ...\PowerShell)
 *     - SmartScreen off:
 *         EnableSmartScreen / SmartScreen = 0 | off | disable
 *     - Breadth bonus: same host tampering distinct security keys inside
 *         the short window escalates the score.
 *
 * EXPLICITLY NOT COVERED (owned by other detectors - do NOT match):
 *     - Defender engine tamper            -> av_tamper (T1562.001)
 *     - Run-key autostart                 -> registry_persistence (T1547.001)
 *     - COM / Winlogon hijack             -> com_hijack / winlogon_hijack
 *     - Service DLL hijack                -> service_dll_hijack
 *     - File association hijack           -> file_assoc
 *     - Screensaver persistence           -> screensaver_persist
 *     - WDigest SecurityProviders (EDR-260), AlwaysInstallElevated (EDR-295),
 *       Terminal Server / RDP-Tcp / LSA DisableRestrictedAdmin
 *       (EDR-296/297/298). These keys are deliberately NOT in the
 *       monitored value-name set below, so there is zero overlap.
 *
 * DUAL REG_WRITE SHAPE (house trap):
 *   driver / imonitor shape : kRegKey = bare key path,
 *                             kRegValue = value name
 *   snapshot shape (sysmon / reg_watch / reg_baseline):
 *                             kRegKey = full path incl. value name,
 *                             kRegValue = data
 *   We resolve the targeted value name from BOTH kRegValue (driver shape)
 *   and the last path component of kRegKey (snapshot shape), so either
 *   shape hits the same detection.
 *
 * SCORING (house rule): >=75 -> "malicious"; 55..74 -> "suspicious";
 *   <55 -> write nothing (fully silent). Score below cfg.minScore also
 *   silent.
 *
 *   per-key intrinsic base (see DescribeValue):
 *     EnableLUA 75 | ConsentPromptBehaviorAdmin 70 | PromptOnSecureDesktop 70
 *     | FilterAdministratorToken 70 | RunAsPPL 70
 *     | LocalAccountTokenFilterPolicy 65 | ExecutionPolicy 65
 *     | LmCompatibilityLevel 60 | NoLMHash 60 | LimitBlankPasswordUse 60
 *     | RestrictAnonymous 60 | DisableDomainCreds 60
 *     | RequireSecuritySignature 55 | SmartScreen 55
 *   breadth bonus: score = min(100, peakBase + (distinctKeys-1) * 19)
 *     distinct=1 -> base            (>=55, always alerts for a real tamper)
 *     distinct=2 -> base+19         (e.g. 55 -> 74, still suspicious)
 *     distinct>=3 -> escalates past 75 into malicious
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_REG_MODIFY_DETECTOR_H
#define EDR_REG_MODIFY_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class RegModifyDetector {
public:
    RegModifyDetector(bool enabled, uint32_t minScore,
                      uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_hosts.size(); }

private:
    struct HostState {
        uint64_t lastSeen100ns = 0;
        std::map<std::string, uint64_t> keys;  // valueName -> lastSeen100ns
    };

    void Stamp(Event& event, uint32_t score,
               const std::vector<std::string>& signals,
               const std::vector<std::string>& techniques) const;

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    std::unordered_map<std::string, HostState> m_hosts;
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
    static constexpr uint32_t kBreadthStep = 19u;

    /* Correlation ("episode") window for the per-host breadth set.
     * Deliberately SEPARATE from m_dedupWindow100ns: the dedup window only
     * suppresses re-alerting the same (host, value) pair, it must NOT drive
     * breadth-key expiry. Conflating them made dedup_window_seconds=0
     * (documented as "dedup disabled") collapse the breadth set on every
     * event, so multi-key escalation silently stopped working. Hardcoded per
     * the batch contract (extra thresholds are constants, not config keys). */
    static constexpr uint64_t kEpisodeWindow100ns = 900ULL * kFiletimeTicksPerSecond;
};

} // namespace edr

#endif /* EDR_REG_MODIFY_DETECTOR_H */
