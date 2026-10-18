/*
 * local_account_detector.h - Local user / privileged group change detector
 * (T1136.001 / T1098.001).
 *
 * Detects suspicious user creation, privilege enablement, and privileged
 * group membership changes from LOCAL_ACCOUNT events emitted by the local
 * account monitor collector (enable_local_account_monitor).
 */
#ifndef EDR_LOCAL_ACCOUNT_DETECTOR_H
#define EDR_LOCAL_ACCOUNT_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class LocalAccountDetector {
public:
    LocalAccountDetector();

    void Enrich(Event& event);

    static bool Inspects(uint16_t type) { return type == EDR_EVT_LOCAL_ACCOUNT; }

    static uint32_t ScoreEvent(const Event& event, std::string& signals);

private:
    static bool IsPrivilegedGroup(const std::string& group);
    static bool IsSuspiciousUser(const std::string& name);
};

} // namespace edr

#endif /* EDR_LOCAL_ACCOUNT_DETECTOR_H */
