/*
 * share_change_detector.h - Network share creation/tamper detector
 * (T1021.002 / T1070.005).
 *
 * Detects adversaries creating SMB shares for lateral movement or file
 * staging, shares pointing at sensitive/root directories, and removal of
 * shares to clean up artifacts. Consumes SHARE_CHANGE events emitted by the
 * share monitor collector (enable_share_monitor).
 */
#ifndef EDR_SHARE_CHANGE_DETECTOR_H
#define EDR_SHARE_CHANGE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ShareChangeDetector {
public:
    ShareChangeDetector();

    void Enrich(Event& event);

    static bool Inspects(uint16_t type) { return type == EDR_EVT_SHARE_CHANGE; }

    static uint32_t ScoreEvent(const Event& event, std::string& signals);

private:
    static bool IsSensitivePath(const std::string& path);
};

} // namespace edr

#endif /* EDR_SHARE_CHANGE_DETECTOR_H */
