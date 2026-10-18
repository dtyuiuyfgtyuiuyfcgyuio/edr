/*
 * lateral_chain_detector.h - Multi-vector lateral-movement chain correlator.
 *
 * Complements the existing lateral detectors, which each look at a single
 * surface:
 *   lateral_movement_detector.cpp  many distinct destinations (network fan-out)
 *   lateral_transfer_detector.cpp  tool transfer over SMB/admin shares (T1570)
 *   remote_exec_detector.cpp       remote execution tool command lines
 *   winrm_abuse_detector.cpp       WinRM command surface
 *
 * This detector answers a different question: did this host accumulate
 * *distinct lateral-movement mechanisms* in a short window? An operator who
 * only sprays one destination with one tool looks like noise on each single
 * surface; an operator who combines remote service creation, an inbound
 * remote logon, admin-share access and a remote-execution tool on the same
 * host within minutes is a chain (T1021 + T1570 + T1569.002).
 *
 * Vector weights (each counted once per host window):
 *   remote_service   20  service install with a remote-invocation shape
 *   remote_logon     20  logon type 3 (network) or 10 (remote interactive)
 *   admin_share      15  SMB/admin-share file access or transfer
 *   remote_exec      15  PsExec/WMIC/WinRM/atexec-style execution
 *   session_reuse    10  explicit credential use / pass-the-hash shape
 *   discovery        10  host enumeration against remote targets
 *
 * Score = sum of distinct vector weights, then a breadth bonus when four or
 * more distinct vectors appear (all four families at once is not something a
 * legitimate admin console does in one window), capped at 100.
 *
 * Attribution: state is per attribution key derived from the event's own
 * host-facing identity. Events with neither pid nor image are skipped.
 * Bounded time-expiring LRU, swept lazily on every Enrich.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_LATERAL_CHAIN_DETECTOR_H
#define EDR_LATERAL_CHAIN_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class LateralChainDetector {
public:
    LateralChainDetector(bool enabled, uint32_t minScore,
                         uint32_t windowSeconds, uint32_t dedupWindowSeconds,
                         size_t stateCapacity);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects. */
    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_states.size(); }

private:
    enum Vector : uint8_t {
        VectorNone = 0,
        VectorRemoteService = 1u << 0,
        VectorRemoteLogon = 1u << 1,
        VectorAdminShare = 1u << 2,
        VectorRemoteExec = 1u << 3,
        VectorSessionReuse = 1u << 4,
        VectorDiscovery = 1u << 5,
    };

    struct KeyState {
        uint8_t mask = 0;
        std::vector<uint8_t> order;
        std::vector<std::string> evidence;
        std::string remoteHost;
        int peakScore = 0;
        bool flagged = false;
        uint64_t lastSeen100ns = 0;
        uint64_t lastFlag100ns = 0;
    };

    static uint8_t VectorFor(const Event& event, std::string& evidence,
                             std::string& remoteHost);
    static uint32_t WeightFor(uint8_t vector);
    static std::string AttributionKey(const Event& event);
    static const char* VectorName(uint8_t bit);

    void PurgeExpired(uint64_t now100ns);
    int ScoreOf(const KeyState& state) const;
    void WriteState(Event& event, const KeyState& state, int score);
    bool InCooldown(const KeyState& state, uint64_t now100ns) const;

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_window100ns;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;
    std::unordered_map<std::string, KeyState> m_states;
};

} // namespace edr

#endif /* EDR_LATERAL_CHAIN_DETECTOR_H */
