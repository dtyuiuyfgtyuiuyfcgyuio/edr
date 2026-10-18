/*
 * dev_util_proxy_detector.h - Trusted developer utilities proxy
 * execution detector (T1127 / T1218.004).
 *
 * Scores inbox Microsoft build/compile/install utilities used as
 * code-execution proxies from user-writable paths:
 *   - MSBuild CodeTaskFactory / InlineTask / UsingTask            -> 90
 *   - csc.exe compiling from temp/appdata/users                   -> 85
 *   - InstallUtil.exe loading a non-system DLL/EXE                -> 85
 *   - jsc.exe / ilasm.exe from a user-writable path               -> 80
 *   - Microsoft.Workflow.Compiler.exe                             -> 80
 *   - MSBuild user-writable .proj/.csproj/.xml                    -> 75
 *   - vbc.exe compiling from a user-writable path                 -> 75
 *
 * Complements static rule EDR-030 (MSBuild temp .proj image regex)
 * with graded verdicts, InstallUtil/csc/jsc/ilasm/vbc coverage, and
 * the script plane. Bare msbuild/csc/vbc with no payload stays silent.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_DEV_UTIL_PROXY_DETECTOR_H
#define EDR_DEV_UTIL_PROXY_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class DevUtilProxyDetector {
public:
    DevUtilProxyDetector(bool enabled, uint32_t minScore,
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

    bool Analyze(const std::string& lower, const std::string& imageLower,
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

#endif /* EDR_DEV_UTIL_PROXY_DETECTOR_H */
