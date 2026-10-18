/*
 * hidden_window_detector.h - Hidden / concealed window execution
 * detector (T1564.003 Hidden Window, T1036.004 Masquerade of task).
 *
 * Adversaries hide windows via PowerShell -WindowStyle Hidden,
 * CREATE_NO_WINDOW, STARTF_USESHOWWINDOW, start /min /b, or
 * conhost hidden switches. Scoring:
 *   - WindowStyle Hidden / -w hidden                 -> 85
 *   - CREATE_NO_WINDOW / UseShowWindow hidden         -> 85
 *   - start /min or /b with payload                  -> 80
 *   - powershell hidden + -enc / download cradle     -> 90
 *   - bare hidden flag without payload               -> 75
 */
#ifndef EDR_HIDDEN_WINDOW_DETECTOR_H
#define EDR_HIDDEN_WINDOW_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include "edr_event.h"
#include "event_bus.h"

namespace edr {
class HiddenWindowDetector {
public:
    HiddenWindowDetector(bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds, size_t stateCapacity);
    void Enrich(Event& event);
    static bool Inspects(uint16_t type);
private:
    struct Finding { uint32_t score=0; const char* signal=""; };
    bool Analyze(const std::string& lower, const std::string& raw, Finding* out) const;
    void Stamp(Event& event, const Finding& finding, const std::string& key);
    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;
    std::unordered_map<std::string,uint64_t> m_lastAlert;
    static constexpr uint64_t kFiletimeTicksPerSecond=10000000ULL;
};
} // namespace edr
#endif
