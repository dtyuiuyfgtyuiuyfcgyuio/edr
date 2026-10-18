/*
 * masquerade_detector.h - Filename-level masquerading detector (T1036).
 *
 * Scope note: "protected system basename launched from the wrong
 * directory" is already covered by ProcessHollowingDetector (and
 * RAT_MASQUERADE_PATH inside the RAT analyzer). This detector covers
 * the complementary filename-disguise families over PROCESS_START:
 *   - RTLO (U+202E) character in the image path          -> 85
 *   - system-binary lookalike basename (svch0st.exe,
 *     scvhost.exe, 1sass.exe, ...)                        -> 80
 *   - double extension ("invoice.pdf.exe")                -> 70
 *   - whitespace-padded executable name ("setup .exe",
 *     trailing dots)                                       -> 60
 *
 * Alerts are deduplicated per image path inside the dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_MASQUERADE_DETECTOR_H
#define EDR_MASQUERADE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class MasqueradeDetector {
public:
    MasqueradeDetector(bool enabled, uint32_t minScore,
                       uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& rawPath, Finding* out) const;
    void Stamp(Event& event, const Finding& finding,
               const std::string& imagePath);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    std::unordered_set<std::string> m_lookalikeNames;
    /* lowercase image path -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_MASQUERADE_DETECTOR_H */
