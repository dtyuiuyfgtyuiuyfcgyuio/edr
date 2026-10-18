/*
 * ntlm_relay_detector.h - NTLM relay attack detector (MITRE T1550.001).
 *
 * Correlates security log NTLM Type-3 (network) logon events that indicate
 * relay attacks:
 *  - Multiple NTLM Type-3 logons from different source IPs to the same
 *    target account within a short window
 *  - NTLM logons where the source workstation differs from the target
 *    machine's expected identity
 *  - Chains of NTLM logons (A->B, B->C) suggesting relay forwarding
 * Events are stamped with ntlm_relay_* fields when confirmed.
 */
#ifndef EDR_NTLM_RELAY_DETECTOR_H
#define EDR_NTLM_RELAY_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class NtlmRelayDetector {
public:
    NtlmRelayDetector(bool enabled, uint32_t windowSeconds,
                      size_t stateCapacity, uint32_t minEvents);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_accounts.size(); }

private:
    struct AccountState {
        std::unordered_set<std::string> sourceIps;
        std::unordered_set<std::string> sourceWorkstations;
        std::map<uint64_t, std::string> timeline;
        uint64_t lastSeen100ns = 0;
    };

    static bool IsNtlmLogon(const Event& event);
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const AccountState& state) const;
    std::string SignalList(const AccountState& state) const;
    std::string SourceList(const AccountState& state) const;
    std::string AccountList(const AccountState& state) const;
    void WriteState(Event& event, const AccountState& state,
                    const std::string& account);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minEvents;
    std::unordered_map<std::string, AccountState> m_accounts;
};

} // namespace edr

#endif /* EDR_NTLM_RELAY_DETECTOR_H */
