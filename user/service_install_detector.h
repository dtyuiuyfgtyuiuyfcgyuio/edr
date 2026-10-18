/*
 * service_install_detector.h - Suspicious service installation detector
 * (MITRE T1543.003 Windows Service / T1569.002 System Processes).
 *
 * Consumes EDR_EVT_SERVICE_INSTALL events (Security log 4697) and flags
 * adversary service creation patterns:
 *  - Binary path in transient/user-writable directories
 *  - LOLBin interpreters as the service binary (powershell, mshta, ...)
 *  - Encoded PowerShell payloads in the image path
 *  - Web payloads or UNC paths pulled at service start
 * Events are stamped with svc_install_* fields when confirmed.
 */
#ifndef EDR_SERVICE_INSTALL_DETECTOR_H
#define EDR_SERVICE_INSTALL_DETECTOR_H

#include <cstdint>
#include <string>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ServiceInstallDetector {
public:
    explicit ServiceInstallDetector(bool enabled);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type) {
        return type == EDR_EVT_SERVICE_INSTALL;
    }

private:
    bool m_enabled;
};

} // namespace edr

#endif /* EDR_SERVICE_INSTALL_DETECTOR_H */
