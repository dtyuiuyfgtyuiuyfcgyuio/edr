/*
 * net_share_discovery_detector.h - Network share discovery burst detector
 * (T1135 Network Share Discovery).
 *
 * Scores PROCESS_START command lines and POWERSHELL_SCRIPT bodies that
 * enumerate reachable SMB/CIFS shares:
 *
 *   - net view / net.exe view / net1 view (incl. UNC-bearing forms)  (T1135)
 *   - net use / net1 use enumeration of mounted shares                 (T1135)
 *   - direct UNC directory listing (dir, ls, Get-ChildItem, gci)        (T1135)
 *   - wmic share get / Get-CimInstance Win32_Share / Get-SmbShare       (T1135)
 *   - PowerShell .NET UNC reads (New-Object Net.WebClient +
 *     DownloadString / DownloadFile against a \\host\share path)        (T1135)
 *
 * A *single* share probe is routine administration and stays silent. The
 * detector fires only on a burst: an actor (keyed by image basename plus
 * user sid / session) issuing at least minCommands DISTINCT share-discovery
 * commands inside the rolling window. Identical command text is deduped, so
 * the same net view replayed repeatedly never crosses the threshold.
 *
 * Complements NetDiscoveryDetector (T1018 / T1049): that one's category set
 * is fixed at netview/netstat/adrecon/ping/arp and covers remote-system and
 * connection-state discovery rather than share enumeration. Complements
 * ShareChangeDetector (T1021.002 / T1070.005), which watches share
 * *configuration* changes, not share discovery.
 *
 * Score ladder: 3 distinct commands -> 60, 4 -> 70, 5 -> 75, 6+ -> 85;
 * +10 when the burst mixes a local-enumeration form with a remote-UNC form
 * (the enumeration-then-pivot shape), +10 when the burst is privileged,
 * both capped at 100. >= 55 suspicious, >= 75 malicious.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_NET_SHARE_DISCOVERY_DETECTOR_H
#define EDR_NET_SHARE_DISCOVERY_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class NetShareDiscoveryDetector {
public:
    NetShareDiscoveryDetector(bool enabled, uint32_t minScore,
                              uint32_t windowSeconds, uint32_t minCommands,
                              uint32_t dedupWindowSeconds,
                              size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_actors.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        uint32_t commandCount = 0;
        std::string targets; /* distinct UNC targets, comma-joined */
        const char* signal = "";
    };

    /* Classify lowered command text into a share-discovery shape. Returns
     * false when the text probes no share. *localEnum and *remoteUnc mark
     * the enumeration-then-pivot split. */
    static bool Classify(const std::string& lower, bool* localEnum,
                         bool* remoteUnc);

    bool Analyze(Event& event, Finding* out);
    void Stamp(Event& event, const Finding& finding) const;
    void PurgeExpired(uint64_t now100ns);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_window100ns;
    uint32_t m_minCommands;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    struct ActorState {
        /* distinct normalized command snippet -> last seen ts100ns */
        std::unordered_map<std::string, uint64_t> commands;
        /* distinct UNC targets, rebuilt from the surviving commands */
        std::unordered_set<std::string> targets;
        uint64_t lastSeen100ns = 0;
        uint64_t lastStamp100ns = 0;
        uint32_t lastFlaggedCount = 0;
        bool localEnum = false;
        bool remoteUnc = false;
        bool privileged = false;
    };
    std::unordered_map<std::string, ActorState> m_actors;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_NET_SHARE_DISCOVERY_DETECTOR_H */