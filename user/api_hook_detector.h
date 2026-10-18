/*
 * api_hook_detector.h - API hook detector.
 *
 * Detects API hooking / tampering of security-relevant functions:
 * - Inline hooks (E9/JMP, push-ret) on critical API entry points
 * - IAT (Import Address Table) tampering
 * - ETW / AMSI function patching (defense evasion)
 * - Known EDR-evasion hooking patterns
 *
 * Inspects ETW_TAMPER, WINDOWS_HOOK, IMAGE_LOAD, PROCESS_ACCESS and
 * MODULE_LOAD-related events. Detection is heuristic; a single hooking
 * event only scores when combined with other suspicious context.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_API_HOOK_DETECTOR_H
#define EDR_API_HOOK_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ApiHookDetector {
public:
    ApiHookDetector(bool enabled, uint32_t minScore,
                    uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects. */
    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_hookStates.size(); }

private:
    struct HookState {
        std::string targetFunction;
        uint32_t score = 0;
        std::vector<std::string> reasons;
        uint64_t lastSeen100ns = 0;
        bool alerted = false;
    };

    void AnalyzeEtwTamper(Event& event);
    void AnalyzeWindowsHook(Event& event);
    void AnalyzeImageLoad(Event& event);
    void AnalyzeProcessAccess(Event& event);

    bool IsCriticalApi(const std::string& lowerFunction) const;
    bool IsEtwProvider(const std::string& lowerGuid) const;
    bool IsAmsiBypassPattern(const std::string& lowerText) const;
    void UpdateScore(HookState& state, uint32_t weight, const char* reason);
    void StampEvent(Event& event, const HookState& state);
    HookState& GetOrCreateState(const std::string& key);
    void PurgeExpired(uint64_t now100ns);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

    std::unordered_map<std::string, HookState> m_hookStates;
};

} // namespace edr

#endif /* EDR_API_HOOK_DETECTOR_H */
