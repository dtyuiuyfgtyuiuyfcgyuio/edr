/*
 * accessibility_hijack_detector.h - Accessibility-feature hijacking (T1546.008).
 *
 * Detects high-confidence replacement or debugger redirection of Windows
 * accessibility binaries, plus execution of those names outside protected
 * System32 locations. Events are stamped with accessibility_hijack_* fields.
 */
#ifndef EDR_ACCESSIBILITY_HIJACK_DETECTOR_H
#define EDR_ACCESSIBILITY_HIJACK_DETECTOR_H

#include <cstdint>
#include <string>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class AccessibilityHijackDetector {
public:
    AccessibilityHijackDetector(bool enabled, uint32_t minScore);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

private:
    void Stamp(Event& event, uint32_t score, const std::string& signal,
               const std::string& target, const std::string& evidence);

    bool m_enabled;
    uint32_t m_minScore;
};

} // namespace edr

#endif /* EDR_ACCESSIBILITY_HIJACK_DETECTOR_H */