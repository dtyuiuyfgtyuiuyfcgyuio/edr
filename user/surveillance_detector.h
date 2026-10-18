/*
 * surveillance_detector.h - User-activity surveillance detector (T1115
 * clipboard data, T1113 screen capture, T1056.001 keylogging, T1125 camera).
 *
 * Consumes the iMonitor surveillance hook events (CLIPBOARD_ACCESS,
 * KEYLOGGER, WALLPAPER_CHANGE, CAMERA_ACCESS) and correlates them per
 * process: when one process accumulates several distinct surveillance
 * signals inside the rolling window (or runs a known surveillance-tool
 * binary), the event is stamped with surveillance_* fields.
 */
#ifndef EDR_SURVEILLANCE_DETECTOR_H
#define EDR_SURVEILLANCE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class SurveillanceDetector {
public:
    SurveillanceDetector(bool enabled, uint32_t windowSeconds,
                         size_t stateCapacity, uint32_t minSignals);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_processes.size(); }

private:
    struct ProcState {
        uint64_t lastSeen100ns = 0;
        std::map<std::string, uint64_t> signals;
        std::string toolName;
    };

    std::string SignalName(uint16_t type) const;
    std::string KnownTool(const std::string& image) const;
    void PurgeExpired(uint64_t now100ns);
    void WriteState(Event& event, const ProcState& state) const;

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minSignals;
    std::unordered_map<uint32_t, ProcState> m_processes;
};

} // namespace edr

#endif /* EDR_SURVEILLANCE_DETECTOR_H */
