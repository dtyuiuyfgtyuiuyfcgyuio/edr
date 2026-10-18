/*
 * indirect_exec_detector.h - Indirect command execution detector
 * (T1202).
 *
 * Scores signed/inbox Windows binaries used as proxies so the real
 * payload is not the process image:
 *   - forfiles.exe /c <command>                                   -> 90
 *   - pcalua.exe -a <payload>                                     -> 85
 *   - ieexec.exe http(s)://...                                    -> 80
 *   - conhost.exe --headless <command>                            -> 75
 *   - ftp.exe -s:<script>                                         -> 70
 *   - presentationhost.exe .xbap/.xaml                            -> 65
 *
 * Complements lolbin_chain / lolbin_parent_child (parent-child shape)
 * and signed_binary_abuse (T1218 mavinject/xwizard plane). Bare
 * forfiles/pcalua/ftp invocation with no payload argument stays silent.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_INDIRECT_EXEC_DETECTOR_H
#define EDR_INDIRECT_EXEC_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class IndirectExecDetector {
public:
    IndirectExecDetector(bool enabled, uint32_t minScore,
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

#endif /* EDR_INDIRECT_EXEC_DETECTOR_H */
