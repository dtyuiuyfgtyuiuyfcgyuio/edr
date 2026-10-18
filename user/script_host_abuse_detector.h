/*
 * script_host_abuse_detector.h - Script host abuse detector
 * (MITRE T1059.005 Visual Basic / T1059.007 JavaScript, T1105 Ingress
 * Tool Transfer, T1218.005 Mshta).
 *
 * Inspects EDR_EVT_PROCESS_START events for the Windows Script Host
 * (wscript.exe / cscript.exe) and mshta.exe. Flags:
 *  - script payloads fetched from remote locations (http/https/UNC share)
 *  - script payloads in transient user-writable locations (temp, downloads,
 *    profile, public) instead of script directories
 *  - encoded/obfuscated command payloads (/e: engine override with a long
 *    base64-looking argument, mshta inline javascript: or vbscript: URLs)
 *  - WSH running an executable proxy payload (.exe/.dll/.bin script target)
 * Events are stamped with script_host_* fields when a signal is found.
 * The detector is stateless: every interesting PROCESS_START is scored
 * immediately, so no windowing/dedup state is kept.
 */
#ifndef EDR_SCRIPT_HOST_ABUSE_DETECTOR_H
#define EDR_SCRIPT_HOST_ABUSE_DETECTOR_H

#include <cstdint>
#include <string>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

struct ScriptHostAbuseSignal {
    bool suspicious = false;
    std::string engine;   /* wscript | cscript | mshta */
    uint32_t score = 0;
    std::string signals;  /* comma-separated signal names */
    std::string verdict;
};

/* Pure classification helper, exposed for unit tests. */
ScriptHostAbuseSignal ClassifyScriptHostCommand(const std::string& image,
                                                const std::string& commandLine);

class ScriptHostAbuseDetector {
public:
    explicit ScriptHostAbuseDetector(bool enabled);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

private:
    bool m_enabled;
};

} // namespace edr

#endif /* EDR_SCRIPT_HOST_ABUSE_DETECTOR_H */
