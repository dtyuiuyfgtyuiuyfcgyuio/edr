/*
 * cred_file_hunt_detector.h - Unsecured credentials in files detector
 * (T1552.001).
 *
 * Flags command/script-plane activity that hunts for or touches files
 * likely to hold plaintext credentials:
 *   - recursive file-content searches for password tokens
 *     (findstr /s, Select-String -Recurse, grep -r, rg)          -> 65-75
 *   - known credential-bearing files referenced on the command
 *     line (passwords.txt, credentials.txt, id_rsa, winscp.ini,
 *     *.kdbx, .netrc ...)                                         -> 65-75
 *   - net use ... /savecred (credential caching for reuse)        -> 65
 *
 * The detector never scores ssh/plink invocations that legitimately
 * reference private keys, and read-only listings of time/attrib never
 * fire. 55+ alerted; 75+ malicious.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_CRED_FILE_HUNT_DETECTOR_H
#define EDR_CRED_FILE_HUNT_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class CredentialFileHuntDetector {
public:
    CredentialFileHuntDetector(bool enabled, uint32_t minScore,
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

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_CRED_FILE_HUNT_DETECTOR_H */
