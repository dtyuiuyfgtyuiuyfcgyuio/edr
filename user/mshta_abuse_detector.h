/*
 * mshta_abuse_detector.h - Mshta proxy execution detector (T1218.005).
 *
 * Detects mshta.exe abused as LOLBIN to execute remote/local HTA,
 * javascript: or vbscript: payloads. Scores by payload type.
 */

#ifndef EDR_MSHTA_ABUSE_DETECTOR_H
#define EDR_MSHTA_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include "edr_event.h"
#include "event_bus.h"

namespace edr {
class MshtaAbuseDetector {
public:
    MshtaAbuseDetector(bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds, size_t stateCapacity);
    void Enrich(Event& event);
    static bool Inspects(uint16_t type);
    size_t StateCount() const { return m_state.size(); }
private:
    struct Finding { uint32_t score=0; const char* signal=""; };
    static bool ClassifyPayload(const std::string& cmdLower, Finding* out);
    void Stamp(Event& e,const Finding& f,const std::string& k);
    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_capacity;
    std::unordered_map<std::string,uint64_t> m_state;
    static constexpr uint64_t kFiletimeTicksPerSecond=10000000ULL;
};
} // namespace edr
#endif
