/*
 * msdt_abuse_detector.h - MSDT / ms-msdt URI abuse detector (T1203).
 *
 * Detects the Follina-style (CVE-2022-30190) abuse of the Microsoft
 * Support Diagnostic Tool: ms-msdt: URI handler invocations (typically
 * from Office documents), msdt.exe reaching remote/UNC payloads or
 * script interpreters, and diagnostic invocations backed by writable
 * paths. Bare msdt.exe stays silent; weaponized shapes score.
 */

#ifndef EDR_MSDT_ABUSE_DETECTOR_H
#define EDR_MSDT_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include "edr_event.h"
#include "event_bus.h"

namespace edr {
class MsdtAbuseDetector {
public:
    MsdtAbuseDetector(bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds, size_t stateCapacity);
    void Enrich(Event& event);
    static bool Inspects(uint16_t type);
    size_t StateCount() const { return m_state.size(); }
private:
    struct Finding { uint32_t score=0; const char* signal=""; };
    static bool ClassifyPayload(const std::string& cmdLower, const std::string& imageLower, const std::string& parentLower, Finding* out);
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
