/*
 * xsl_script_detector.h - XSL script processing detector (T1220).
 *
 * Scores stylesheet-driven code execution that hides the real payload
 * behind wmic / msxsl / MSXML:
 *   - msxsl.exe with a .xsl/.xslt stylesheet                     -> 90
 *   - wmic /format:http(s)://... remote stylesheet               -> 90
 *   - wmic /format: against a user-writable path                 -> 85
 *   - MSXML TransformNode / XslCompiledTransform                 -> 80
 *   - wmic /format: with a local .xsl not in the built-in list   -> 75
 *
 * Complements static rule EDR-285 (wmic /format:http|Users only).
 * Built-in format names (list/table/csv/xml/value/mof/hform/htable)
 * and bare msxsl/wmic invocation stay silent.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_XSL_SCRIPT_DETECTOR_H
#define EDR_XSL_SCRIPT_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class XslScriptDetector {
public:
    XslScriptDetector(bool enabled, uint32_t minScore,
                      uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& lower, const std::string& imageLower,
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

#endif /* EDR_XSL_SCRIPT_DETECTOR_H */
