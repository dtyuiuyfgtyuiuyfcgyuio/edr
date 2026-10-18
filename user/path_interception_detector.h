/*
 * path_interception_detector.h - PATH environment variable hijack
 * detector (T1574.007 / T1574.008).
 *
 * Scores command/script/registry activity that plants or redirects
 * DLL/exe search-order locations:
 *   - setx PATH / [Environment]::SetEnvironmentVariable("Path",...)
 *     pointing at user-writable dirs (%TEMP%, %APPDATA%, \Users\Public,
 *     \ProgramData, \Windows\Temp)                              -> 85
 *   - reg add ... Environment /v Path (machine persistence)      -> 90
 *   - REG_WRITE naming the Environment Path value itself, with a
 *     writable dir in the data (90) or without (75)
 *   - $env:Path / %PATH% assignment prepending a writable dir    -> 80
 *   - generic setx PATH with any value                           -> 65
 *   - PowerShell $env:PATH prepend of a writable dir in a script -> 70
 *
 * Read-only `echo %PATH%` / `$env:PATH` display and gci on PATH stay
 * silent; an assignment to the variable is a write, not a display.
 *
 * The registry plane matches the PATH value name exactly - against
 * kRegValue and against the last component of kRegKey, covering both
 * REG_WRITE shapes - so neighbouring values such as PATHEXT and
 * PSModulePath never fire. Every plane shares one dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_PATH_INTERCEPTION_DETECTOR_H
#define EDR_PATH_INTERCEPTION_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PathInterceptionDetector {
public:
    PathInterceptionDetector(bool enabled, uint32_t minScore,
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

    bool Analyze(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding,
               const std::string& key);
    void StampDeduped(Event& event, const Finding& finding,
                      const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_PATH_INTERCEPTION_DETECTOR_H */
