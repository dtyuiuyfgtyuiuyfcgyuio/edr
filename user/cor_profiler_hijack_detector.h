/*
 * cor_profiler_hijack_detector.h - .NET profiler hijack detector
 * (MITRE T1574.012 COR_PROFILER environment variable hijacking).
 *
 * The .NET runtime loads the COM profiler named by COR_PROFILER into
 * every CLR process when COR_ENABLE_PROFILING=1 - a code-execution
 * primitive that needs no files inside the target process. Flags both
 * planes:
 *   - setx / registry / PowerShell writes of COR_PROFILER (or
 *     CORECLR_PROFILER) to a CLSID                          -> 90
 *   - COR_ENABLE_PROFILING / CORECLR_ENABLE_PROFILING = 1
 *     (arming the profiler without naming it yet)           -> 80
 *   - COR_PROFILER_PATH pointing at a DLL                   -> 85
 *   - combo: arming + naming the profiler in one command     -> 95
 *   - registry Environment-key writes carrying COR_* names   -> 90
 *
 * Deleting/echoing these variables never scores. 55+ alerted;
 * 75+ malicious.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_COR_PROFILER_HIJACK_DETECTOR_H
#define EDR_COR_PROFILER_HIJACK_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class CorProfilerHijackDetector {
public:
    CorProfilerHijackDetector(bool enabled, uint32_t minScore,
                              uint32_t dedupWindowSeconds,
                              size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& lower, bool registryPlane,
                 Finding* out) const;
    void Stamp(Event& event, const Finding& finding,
               const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_COR_PROFILER_HIJACK_DETECTOR_H */
