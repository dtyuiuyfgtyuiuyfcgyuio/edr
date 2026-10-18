/*
 * driver_load_detector.h - Driver load detector.
 *
 * Detects suspicious kernel driver loads:
 * - Unsigned or improperly signed drivers
 * - Known vulnerable drivers (BYOVD - Bring Your Own Vulnerable Driver)
 * - Drivers loaded from user-writable locations
 * - Drivers with suspicious names / properties
 * - Sudden bursts of driver loads
 *
 * Inspects SERVICE_INSTALL, SERVICE_START_HOOK, IMAGE_LOAD and
 * SERVICE_CHANGE events to identify driver-related activity.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_DRIVER_LOAD_DETECTOR_H
#define EDR_DRIVER_LOAD_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class DriverLoadDetector {
public:
    DriverLoadDetector(bool enabled, uint32_t minScore,
                       uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects. */
    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_driverStates.size(); }

private:
    struct DriverState {
        std::string imagePath;
        std::string serviceName;
        std::string signer;
        bool signedDriver = true;
        uint32_t loadCount = 0;
        uint32_t score = 0;
        std::vector<std::string> reasons;
        uint64_t lastSeen100ns = 0;
        bool alerted = false;
    };

    void AnalyzeServiceInstall(Event& event);
    void AnalyzeServiceStart(Event& event);
    void AnalyzeImageLoad(Event& event);

    bool IsKnownVulnerableDriver(const std::string& lowerBase) const;
    bool IsUserWritableLocation(const std::string& lowerPath) const;
    bool IsSuspiciousDriverName(const std::string& lowerBase) const;
    void UpdateScore(DriverState& state, uint32_t weight, const char* reason);
    void StampEvent(Event& event, const DriverState& state);
    DriverState& GetOrCreateState(const std::string& key);
    void PurgeExpired(uint64_t now100ns);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

    std::unordered_map<std::string, DriverState> m_driverStates;
};

} // namespace edr

#endif /* EDR_DRIVER_LOAD_DETECTOR_H */
