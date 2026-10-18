/*
 * hosts_redirect_detector.h - hosts-file traffic redirection detector
 * (T1565.001 Stored Data Manipulation; C2 / phishing preparation).
 *
 * Consumes FILE_INTEGRITY events for the drivers\etc\hosts file and the
 * command/script plane that appends to it:
 *   FILE plane (FILE_INTEGRITY on ...\drivers\etc\hosts only - the FIM
 *   watch list carries unrelated files, so the path is confirmed first):
 *     - hosts modification                                        -> 70
 *     - hosts deletion                                            -> 80
 *   Command plane:
 *     - appended IP-to-domain mapping (echo "1.2.3.4 host"
 *       >> ...hosts)                                             -> 85
 *     - security-vendor update domains pointed at a fixed IP
 *       (defender updates, AV signature hosts)                   -> 90
 *     - generic append/redirect into the hosts file               -> 75
 *
 * Read-only `type ...hosts` display stays silent. Command-plane dedup is
 * keyed on the normalized command text. FILE_INTEGRITY dedup is keyed on
 * (action, path) so a polling FIM re-report of the same action is
 * suppressed, while modified then removed on the same path still stamps.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_HOSTS_REDIRECT_DETECTOR_H
#define EDR_HOSTS_REDIRECT_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class HostsRedirectDetector {
public:
    HostsRedirectDetector(bool enabled, uint32_t minScore,
                          uint32_t dedupWindowSeconds,
                          size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding,
               const std::string& key);
    void StampDeduped(Event& event, const Finding& finding,
                      const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_HOSTS_REDIRECT_DETECTOR_H */
