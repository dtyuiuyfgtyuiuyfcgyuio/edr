/*
 * input_simulation_detector.h - Input simulation abuse detector
 * (MITRE T1517 input capture / T1185 browser session hijacking precursor).
 *
 * Consumes EDR_EVT_INPUT_SIMULATION events (iMonitor emMSGHookSendInput)
 * and flags programs injecting synthetic mouse/keyboard input:
 *  - Any SendInput hook registration from a non-system process
 *  - High-frequency injection bursts (automation / click-fraud /
 *    UAC-bypass keystroke replay patterns)
 * Events are stamped with input_sim_* fields when confirmed.
 */
#ifndef EDR_INPUT_SIMULATION_DETECTOR_H
#define EDR_INPUT_SIMULATION_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class InputSimulationDetector {
public:
    InputSimulationDetector(bool enabled, uint32_t windowSeconds,
                            size_t stateCapacity, uint32_t burstThreshold);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type) {
        return type == EDR_EVT_INPUT_SIMULATION;
    }

    size_t StateCount() const { return m_procs.size(); }

private:
    struct ProcState {
        uint32_t eventCount = 0;
        uint64_t lastSeen100ns = 0;
    };

    static bool IsSystemProcess(const std::string& image);
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const ProcState& state, bool systemProcess) const;
    std::string SignalList(const ProcState& state, bool systemProcess) const;
    void WriteState(Event& event, const ProcState& state, bool systemProcess);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_burstThreshold;
    std::unordered_map<uint32_t, ProcState> m_procs;
};

} // namespace edr

#endif /* EDR_INPUT_SIMULATION_DETECTOR_H */
