/*
 * browser_extension_detector.h - Browser extension persistence detector
 * (MITRE T1176).
 *
 * Detects unpacked Chromium-family extensions loaded from the command line,
 * forced-extension policy writes, and external-extension registry entries.
 * Read-only registry inspection and ordinary browser launches stay silent.
 * Approved policy deployments can be suppressed by exact
 * browser:extension_id@update_host allowlist entries.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_BROWSER_EXTENSION_DETECTOR_H
#define EDR_BROWSER_EXTENSION_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class BrowserExtensionDetector {
public:
    BrowserExtensionDetector(bool enabled, uint32_t minScore,
                             uint32_t dedupWindowSeconds,
                             size_t stateCapacity,
                             const std::vector<std::string>& allowlist = {});

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool AnalyzeBrowserLaunch(const std::string& lowerImage,
                              const std::string& lowerText,
                              Finding* out) const;
    bool AnalyzeRegistryWrite(const std::string& lowerKey,
                              const std::string& lowerValue,
                              bool scriptedWrite,
                              Finding* out) const;
    bool IsAllowlisted(const std::string& browser,
                       const std::string& extensionId,
                       const std::string& updateHost) const;
    bool IsDuplicate(const std::string& key, uint64_t now100ns);
    void Stamp(Event& event, const Finding& finding,
               const std::string& evidence);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;
    std::unordered_set<std::string> m_allowlist;

    /* Normalized evidence -> timestamp of the last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_BROWSER_EXTENSION_DETECTOR_H */
