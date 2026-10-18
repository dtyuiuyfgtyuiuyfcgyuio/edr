/*
 * remote_access_detector.h - Remote access / remote support tool detector.
 *
 * Correlates process starts of known remote-control binaries (AnyDesk,
 * TeamViewer, ToDesk, RustDesk, Splashtop, VNC families, ScreenConnect,
 * LogMeIn, Radmin, etc.) with corroborating telemetry: the tool opening a
 * listening port, creating a named pipe, or being installed as a service.
 * Events are stamped with remote_access_* fields when a confirmed remote
 * access signal is present (MITRE T1219 / T1572).
 */
#ifndef EDR_REMOTE_ACCESS_DETECTOR_H
#define EDR_REMOTE_ACCESS_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class RemoteAccessDetector {
public:
    RemoteAccessDetector(bool enabled, uint32_t windowSeconds,
                         size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_procs.size(); }

private:
    struct ProcState {
        std::string tool;
        bool toolViaProcess = false;
        bool sawService = false;
        bool sawPipe = false;
        bool sawListener = false;
        uint64_t lastSeen100ns = 0;
    };

    static bool IsKnownTool(const std::string& base);
    void PurgeExpired(uint64_t now100ns);
    uint32_t PidOf(const Event& event) const;
    uint32_t ComputeScore(const ProcState& state) const;
    std::string SignalList(const ProcState& state) const;
    void WriteState(Event& event, const ProcState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    std::unordered_map<uint32_t, ProcState> m_procs;
};

} // namespace edr

#endif /* EDR_REMOTE_ACCESS_DETECTOR_H */
