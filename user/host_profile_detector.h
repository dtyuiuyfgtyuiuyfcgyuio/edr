/*
 * host_profile_detector.h - Per-actor host profiling breadth detector
 * (T1007 Process Discovery / T1012 Query Registry / T1016 System Network
 * Configuration Discovery / T1018 Remote System Discovery / T1069 Permission
 * Groups Discovery / T1082 System Information Discovery / T1087 Account
 * Discovery).
 *
 * Scores PROCESS_START command lines by *which host-profile question a single
 * actor is asking*, grouping many narrow commands into a small fixed set of
 * categories:
 *
 *   processes  - tasklist /sc query / Get-Process / Get-CimInstance Win32_Process
 *                / wmic process / driverquery / fltmc                (T1007)
 *   services   - sc query|qc|qdescription / net start / Get-Service
 *                / wmic service / driverquery                          (T1007)
 *   registry   - reg query / Get-ItemProperty HKLM / regedit /export   (T1012)
 *   netconfig  - ipconfig /all / route print / netsh interface show
 *                / Get-NetIPConfiguration / arp -a                     (T1016)
 *   systeminfo - systeminfo / msinfo32 / Get-ComputerInfo
 *                / wmic os get / ver                                  (T1082)
 *   groups     - net localgroup / net group / whoami /groups
 *                / Get-LocalGroup / dsquery group                     (T1069)
 *   accounts   - net user / net accounts / quser / Get-LocalUser
 *                / wmic useraccount                                   (T1087)
 *
 * The detector fires only on *breadth*: an actor (keyed by image basename +
 * owning user) that asks at least m_minCategories distinct profile questions
 * inside the rolling window is stamped with host_profile_score /
 * host_profile_categories / host_profile_category_count /
 * host_profile_window_seconds / host_profile_privileged and a verdict.
 * A single one of these commands is routine administration and stays silent.
 *
 * Complements DiscoveryReconDetector (host-wide, technique buckets keyed by
 * tool family) and NetDiscoveryDetector (single-category bursts against many
 * targets): this one keys on the *actor* and measures how many different
 * profile dimensions one process maps inside one window, which is the
 * enumeration pattern a hands-on-keyboard intruder leaves before pivoting.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_HOST_PROFILE_DETECTOR_H
#define EDR_HOST_PROFILE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class HostProfileDetector {
public:
    HostProfileDetector(bool enabled, uint32_t minScore, uint32_t windowSeconds,
                        uint32_t minCategories, uint32_t dedupWindowSeconds,
                        size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_actors.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        uint32_t categoryCount = 0;
        std::string categories; /* sorted, comma-joined */
        bool privileged = false;
        const char* signal = "";
    };

    /* Classify lowered command line / script text into a profile category.
     * Returns false when the text asks no host-profile question. */
    bool Classify(const std::string& lower, std::string* category) const;

    bool Analyze(Event& event, Finding* out);
    void Stamp(Event& event, const Finding& finding) const;
    void PurgeExpired(uint64_t now100ns);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    uint32_t m_minCategories;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    struct ActorState {
        /* category -> last seen ts100ns inside the rolling window */
        std::unordered_map<std::string, uint64_t> categories;
        uint64_t lastSeen100ns = 0;
        uint64_t lastStamp100ns = 0;
        uint32_t lastFlaggedCount = 0;
        bool privileged = false;
    };
    std::unordered_map<std::string, ActorState> m_actors;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_HOST_PROFILE_DETECTOR_H */
