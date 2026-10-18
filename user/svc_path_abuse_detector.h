/*
 * svc_path_abuse_detector.h - Unquoted service path and weak-permission
 * path hijack detector (T1574.009 Path Interception by Unquoted Path,
 * T1574.010 Services File Permissions Weakness).
 *
 * Both techniques hijack a service's binary without touching the service
 * registration itself, so the persistence detectors stay quiet:
 *   - service ImagePath left unquoted with a space in the path, letting
 *     C:\Program.exe pre-empt C:\Program Files\App\svc.exe       -> 85
 *   - an executable planted at exactly such a pre-empt point       -> 90
 *   - icacls/cacls granting write or full control on a service
 *     binary or its directory to a non-admin principal            -> 85
 *   - sc config binPath rewritten to a user-writable location      -> 80
 *   - service binary overwritten in place by a non-installer       -> 75
 *
 * Only the pre-empt shape scores for the unquoted case: an unquoted path
 * with no space is unexploitable and stays silent, as does a properly
 * quoted path. Complements registry_persistence, which scores the
 * ImagePath VALUE landing somewhere suspicious rather than the quoting
 * and ACL weaknesses that let an attacker hijack a legitimate path.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_SVC_PATH_ABUSE_DETECTOR_H
#define EDR_SVC_PATH_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class SvcPathAbuseDetector {
public:
    SvcPathAbuseDetector(bool enabled, uint32_t minScore,
                         uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

    /* Exposed for unit tests: true when a raw ImagePath string is
     * unquoted AND contains a space before the executable token, which is
     * the only exploitable shape. */
    static bool IsExploitableUnquotedPath(const std::string& imagePath);

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& lower, const std::string& raw,
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

#endif /* EDR_SVC_PATH_ABUSE_DETECTOR_H */
