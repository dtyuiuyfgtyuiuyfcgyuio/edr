/*
 * ssh_abuse_detector.h - SSH remote execution abuse detector
 * (T1021.004 SSH, T1021 Remote Services).
 *
 * Scores PROCESS_START command lines that invoke SSH clients with
 * suspicious options:
 *   - StrictHostKeyChecking=no + UserKnownHostsFile /dev/null|nul -> 90
 *   - -i <identity file> (private key specified)                     -> 80
 *   - -o BatchMode=yes / -o ConnectTimeout etc. with -f/-N          -> 75
 *   - -p <non-standard port>                                         -> 60
 *   - plain ssh.exe / plink.exe remote invocation                    -> 55
 *
 * Boundary-safe: " -i " with spaces, " -p " with spaces, "ssh.exe"
 * lowercased. Dedup with score-upgrade widening.
 */
#ifndef EDR_SSH_ABUSE_DETECTOR_H
#define EDR_SSH_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class SshAbuseDetector {
public:
    SshAbuseDetector(bool enabled, uint32_t minScore,
                     uint32_t dedupWindowSeconds, size_t stateCapacity);
    void Enrich(Event& event);
    static bool Inspects(uint16_t type);
    size_t StateCount() const { return m_state.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };
    struct DedupEntry { uint64_t ts100ns = 0; uint32_t score = 0; };
    bool Analyze(const std::string& lower, const std::string& imageLower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding, const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;
    std::unordered_map<std::string, DedupEntry> m_state;
    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr
#endif
