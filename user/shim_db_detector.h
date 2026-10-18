/*
 * shim_db_detector.h - Application-compatibility shimming detector (T1546.011).
 *
 * Attackers abuse the Application Compatibility engine to run custom shim
 * databases that redirect or patch the execution of targeted binaries.
 * Persistence/evasion planes this detector grades:
 *   - sdbinst.exe installing a custom .sdb shim database               -> 85
 *   - bare sdbinst.exe invocation (shim tooling)                       -> 60
 *   - registry write under AppCompatFlags\Custom (custom shim entry)   -> 90
 *   - registry write under AppCompatFlags\InstalledSDB (db registered) -> 80
 *   - a .sdb shim database staged into a user-writable path            -> 55
 *
 * sdbinst uninstalls (-q -u) are not scored. Windows's own compatibility
 * DBs live under the same parent key but never in \Custom\, which is the
 * attacker-controlled surface.
 *
 * Alerts are deduplicated per signal key inside the dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_SHIM_DB_DETECTOR_H
#define EDR_SHIM_DB_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ShimDbDetector {
public:
    ShimDbDetector(bool enabled, uint32_t minScore,
                   uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        std::string path;
    };

    bool AnalyzeProcessStart(const std::string& image,
                             const std::string& commandLine,
                             Finding* out) const;
    bool AnalyzeRegWrite(const std::string& regKey, Finding* out) const;
    bool AnalyzeFileCreate(const std::string& filePath, Finding* out) const;
    void Stamp(Event& event, const Finding& finding);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_SHIM_DB_DETECTOR_H */
