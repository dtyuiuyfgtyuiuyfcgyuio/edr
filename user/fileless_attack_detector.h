/*
 * fileless_attack_detector.h - Fileless attack detector.
 *
 * Detects fileless / in-memory attack techniques:
 * - PowerShell script blocks with obfuscation / download-execute patterns
 * - WMI event subscriptions used for fileless persistence
 * - Script hosts (wscript/cscript/mshta) spawning with encoded payloads
 * - Memory-resident only payloads (no backing executable)
 * - Reflective DLL load indicators
 *
 * Inspects POWERSHELL_SCRIPT, WMI_EVENT, PROCESS_START, THREAD_CREATE
 * and PROCESS_ACCESS events.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_FILELESS_ATTACK_DETECTOR_H
#define EDR_FILELESS_ATTACK_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class FilelessAttackDetector {
public:
    FilelessAttackDetector(bool enabled, uint32_t minScore,
                           uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects. */
    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_scriptStates.size(); }

private:
    struct ScriptState {
        std::string scriptId;
        uint32_t score = 0;
        std::vector<std::string> techniques;
        uint64_t lastSeen100ns = 0;
        bool alerted = false;
    };

    void AnalyzePowerShell(Event& event);
    void AnalyzeWmi(Event& event);
    void AnalyzeProcessStart(Event& event);
    void AnalyzeThreadCreate(Event& event);
    void AnalyzeProcessAccess(Event& event);

    bool ContainsObfuscation(const std::string& text) const;
    bool ContainsDownloadExecute(const std::string& text) const;
    bool ContainsReflection(const std::string& text) const;
    bool IsScriptHost(const std::string& lowerBase) const;
    void UpdateScore(ScriptState& state, uint32_t weight,
                     const char* technique);
    void StampEvent(Event& event, const ScriptState& state);
    ScriptState& GetOrCreateState(const std::string& key);
    void PurgeExpired(uint64_t now100ns);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

    std::unordered_map<std::string, ScriptState> m_scriptStates;
};

} // namespace edr

#endif /* EDR_FILELESS_ATTACK_DETECTOR_H */
