/*
 * winlogon_hijack_detector.h - Winlogon persistence detector (T1547.004).
 *
 * Monitors HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
 * values Userinit, Shell, Notify, GinaDLL, etc. Hijacking these lets
 * attackers execute on logon as SYSTEM.
 *
 * Scores: writable/interpreter -> 90, non-system32 -> 85, name-only -> 75,
 * system32 defaults silent (userinit.exe, explorer.exe).
 */

#ifndef EDR_WINLOGON_HIJACK_DETECTOR_H
#define EDR_WINLOGON_HIJACK_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class WinlogonHijackDetector {
public:
    WinlogonHijackDetector(bool enabled, uint32_t minScore,
                           uint32_t dedupWindowSeconds, size_t stateCapacity);
    void Enrich(Event& event);
    static bool Inspects(uint16_t type);
    size_t StateCount() const { return m_state.size(); }
private:
    struct Finding { uint32_t score=0; const char* signal=""; };
    static bool ClassifyPayload(const std::string& data, Finding* out);
    void Stamp(Event& event, const Finding& f, const std::string& key);
    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_capacity;
    std::unordered_map<std::string, uint64_t> m_state;
    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr
#endif
