/*
 * browser_theft_detector.h - Browser credential/data theft detector
 * (MITRE T1555.003).
 *
 * Detects processes accessing browser credential databases, cookie stores,
 * and sensitive profile data outside the browser process itself.
 * Monitors file access to:
 *  - Chrome/Edge: Login Data, Cookies, Web Data, Local State
 *  - Firefox: logins.json, key4.db, cookies.sqlite, formhistory.sqlite
 * Events are stamped with browser_theft_* fields when confirmed.
 */
#ifndef EDR_BROWSER_THEFT_DETECTOR_H
#define EDR_BROWSER_THEFT_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class BrowserTheftDetector {
public:
    BrowserTheftDetector(bool enabled, uint32_t windowSeconds,
                         size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_procs.size(); }

private:
    struct ProcState {
        std::unordered_set<std::string> browsers;
        std::unordered_set<std::string> dataTypes;
        bool sawLocalState = false;
        uint64_t lastSeen100ns = 0;
    };

    static bool IsBrowserProcess(const std::string& image);
    static bool IdentifyBrowserData(const std::string& path,
                                    std::string& browser,
                                    std::string& dataType);
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const ProcState& state) const;
    std::string BrowserList(const ProcState& state) const;
    std::string DataTypeList(const ProcState& state) const;
    void WriteState(Event& event, const ProcState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    std::unordered_map<uint32_t, ProcState> m_procs;
};

} // namespace edr

#endif /* EDR_BROWSER_THEFT_DETECTOR_H */
