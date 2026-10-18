/*
 * iis_module_detector.h - IIS module / ISAPI persistence detector
 * (T1505.004).
 *
 * Scores installation of native IIS extensions:
 *   - appcmd add/install module or ISAPI filter                   -> 90
 *   - New-WebGlobalModule / Add-WebConfiguration globalModules    -> 85
 *   - applicationHost.config overwrite / copy                     -> 80
 *   - FILE_CREATE of a .dll under inetsrv or inetpub by a
 *     non-IIS installer process                                   -> 75
 *
 * Read-only appcmd list / Get-WebGlobalModule stay silent.
 * Complements webshell (T1505.003 script drops).
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_IIS_MODULE_DETECTOR_H
#define EDR_IIS_MODULE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class IisModuleDetector {
public:
    IisModuleDetector(bool enabled, uint32_t minScore,
                      uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& lower, Finding* out) const;
    bool AnalyzeFile(const std::string& lowerPath,
                     const std::string& lowerImage, Finding* out) const;
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

#endif /* EDR_IIS_MODULE_DETECTOR_H */
