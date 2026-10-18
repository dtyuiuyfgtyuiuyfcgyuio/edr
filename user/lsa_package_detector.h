/*
 * lsa_package_detector.h - LSA security-package / password-filter
 * persistence detector (T1547.005 / T1556.002).
 *
 * Scores command and registry-plane arming of extra LSA packages:
 *   - mimikatz memssp / mimilib SSP injection                    -> 90
 *   - REG_WRITE Security/Authentication/Notification Packages    -> 90
 *   - reg add / Set-ItemProperty of those LSA values             -> 85
 *
 * Read-only reg query / Get-ItemProperty stay silent. Complements
 * registry_persistence, which only tags the LSA key as a chain
 * mechanism rather than grading the single write.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_LSA_PACKAGE_DETECTOR_H
#define EDR_LSA_PACKAGE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class LsaPackageDetector {
public:
    LsaPackageDetector(bool enabled, uint32_t minScore,
                       uint32_t dedupWindowSeconds, size_t stateCapacity);

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

#endif /* EDR_LSA_PACKAGE_DETECTOR_H */
