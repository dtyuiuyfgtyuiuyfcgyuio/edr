/*
 * golden_ticket_detector.h - Kerberos forged ticket detector
 * (MITRE T1558.001 golden ticket / T1558.003 silver ticket usage).
 *
 * Kerberos events surfaced by the security log parser (4768/4769,
 * normalized as LOGON TGT_REQUEST / TGS_REQUEST) are inspected for
 * forged-ticket shapes:
 *  - TGT requested with RC4-HMAC (0x17) encryption - golden tickets are
 *    minted with the krbtgt NTLM hash and default to RC4 (80)
 *  - TGT requested directly for the krbtgt account (90)
 *  - Service tickets requested for the krbtgt account - golden-ticket
 *    usage pattern (85)
 *  - Repeated RC4 TGT requests from one source inside the window (90)
 *  - RC4 service tickets for krbtgt - strongest combined shape (100)
 * Events are stamped with golden_ticket_* fields when confirmed.
 */
#ifndef EDR_GOLDEN_TICKET_DETECTOR_H
#define EDR_GOLDEN_TICKET_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class GoldenTicketDetector {
public:
    GoldenTicketDetector(bool enabled, uint32_t windowSeconds,
                         size_t stateCapacity, uint32_t minRepeatCount);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_sources.size(); }

private:
    struct SourceState {
        uint32_t rc4TgtCount = 0;
        bool sawKrbtgtTgt = false;
        bool sawKrbtgtTgs = false;
        std::unordered_set<std::string> targets;
        uint64_t lastSeen100ns = 0;
    };

    static bool IsRc4Encryption(const std::string& encryptionType);
    static bool IsKrbtgtAccount(const std::string& targetUser);
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const SourceState& state) const;
    std::string SignalList(const SourceState& state) const;
    void WriteState(Event& event, const SourceState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minRepeatCount;
    std::unordered_map<std::string, SourceState> m_sources;
};

} // namespace edr

#endif /* EDR_GOLDEN_TICKET_DETECTOR_H */
