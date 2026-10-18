/*
 * av_tamper_detector.h - AV / EDR tampering detector (T1562.001).
 *
 * Scores PROCESS_START command lines, POWERSHELL_SCRIPT bodies and
 * REG_WRITE events that disable or blind security tooling:
 *   - Set-MpPreference disabling an engine capability
 *     (DisableRealtimeMonitoring, DisableBehaviorMonitoring,
 *      DisableIOAVProtection, DisableScriptScanning,
 *      DisableIntrusionPreventionSystem, ...)              -> 90
 *   - Set-MpPreference adding an exclusion
 *     (exclusion path/process/extension/IP)                -> 80
 *   - MpCmdRun.exe -RemoveDefinitions / signature wipe     -> 75
 *   - uninstall / stop of a protected service image
 *     (windefend, sense, mscorlit...) via sc / wmic /
 *     Remove-MpPreference force flag                        -> 85
 *   - tamper policy registry writes: DisableAntiSpyware /
 *     DisableRealtimeMonitoring under Defender's Policies key,
 *     UAC-less WDigest UseLogonCredential re-enable         -> 85
 *
 * The defense_evasion detector already covers generic service stop /
 * config change against protected names (EDR-0xx family); this
 * detector covers the Defender-specific configuration plane:
 * PowerShell cmdlet tampering, exclusions, definition removal and
 * policy registry values.
 *
 * Alerts are deduplicated per signal key inside the dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_AV_TAMPER_DETECTOR_H
#define EDR_AV_TAMPER_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class AvTamperDetector {
public:
    AvTamperDetector(bool enabled, uint32_t minScore,
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
    bool AnalyzeRegistryWrite(const std::string& lowerKey,
                              const std::string& lowerValue,
                              Finding* out) const;
    void Stamp(Event& event, const Finding& finding);
    bool DedupGate(const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_AV_TAMPER_DETECTOR_H */
