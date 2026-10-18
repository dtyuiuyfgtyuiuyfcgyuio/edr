/*
 * dll_hijack_detector.h - DLL search-order hijack / sideload detector.
 *
 * Inspects EDR_EVT_IMAGE_LOAD events. A known system DLL loaded from a
 * user-writable location is a strong search-order-hijack or DLL-sideload
 * signal. This detector is intentionally opt-in because some applications
 * legitimately ship private copies of common DLL names in their install
 * directories; the detector only flags temp/download/profile/public/
 * ProgramData locations, not normal Program Files or Windows paths.
 */
#ifndef EDR_DLL_HIJACK_DETECTOR_H
#define EDR_DLL_HIJACK_DETECTOR_H

#include <cstdint>
#include <string>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

struct DllHijackSignal {
    bool suspicious = false;
    std::string name;
    std::string location;
    uint32_t score = 0;
    std::string verdict;
};

DllHijackSignal ClassifyDllHijackPath(const std::string& imagePath);

class DllHijackDetector {
public:
    explicit DllHijackDetector(bool enabled);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

private:
    bool m_enabled;
};

} // namespace edr

#endif /* EDR_DLL_HIJACK_DETECTOR_H */
