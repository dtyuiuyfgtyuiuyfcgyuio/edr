/*
 * dll_search_order_detector.h - DLL search order hijack detector (T1574.002).
 *
 * Scores the write plane that plants a DLL where Windows will find it
 * before System32 due to the default search order (application directory
 * first, then System32). The load plane (image_loaded from a writable
 * location) is already covered by dll_hijack_detector; this detector
 * covers the complementary write/registry plane.
 *
 *   - FILE_CREATE of a .dll into an application image directory
 *     (...\Program Files\...\*.dll)                              -> 85
 *   - FILE_CREATE of a .dll into a user-writable directory
 *     (Temp/AppData/Public/ProgramData/Downloads)                -> 80
 *   - REG_WRITE to Session Manager\KnownDLLs pointing outside
 *     system32 or into a writable directory                      -> 90
 *   - command plane "SetDllDirectory" / "KnownDLLs" with a
 *     writable / non-system payload path                         -> 75
 *
 * Read-only queries, TrustedInstaller/msiexec writes and writes
 * whose target stays inside \windows\system32\ stay silent.
 *
 * Thread-safety: single EventBus consumer thread only.
 */
#ifndef EDR_DLL_SEARCH_ORDER_DETECTOR_H
#define EDR_DLL_SEARCH_ORDER_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class DllSearchOrderDetector {
public:
    DllSearchOrderDetector(bool enabled, uint32_t minScore,
                           uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_state.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    static bool ClassifyFileWrite(const std::string& path, Finding* out);
    static bool ClassifyKnownDllPayload(const std::string& data, Finding* out);

    void Stamp(Event& event, const Finding& finding, const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_capacity;
    std::unordered_map<std::string, uint64_t> m_state;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_DLL_SEARCH_ORDER_DETECTOR_H */
