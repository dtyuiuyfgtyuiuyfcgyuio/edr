/*
 * attack_chain_detector.h - Per-process attack-chain (tactic) detector.
 *
 * Accumulates MITRE tactic bits per strong process instance and
 * writes the running chain onto each inspected event (attack_chain_stages/
 * attack_chain_stage_count/attack_chain_tactics/attack_chain_score). State
 * is a bounded, time-expiring LRU; expired entries are swept lazily at most
 * once per window. Enrichment is best-effort and never throws.
 *
 * Exact PID+creation identities are provider-neutral; opaque identities are
 * endpoint/producer-scoped. Weak identities never accumulate across events.
 * Stops retire only the named instance; unidentified starts invalidate that
 * endpoint's old PID context without importing its tactics.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_ATTACK_CHAIN_DETECTOR_H
#define EDR_ATTACK_CHAIN_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class AttackChainDetector {
public:
    AttackChainDetector(size_t stateCapacity, uint32_t windowSeconds);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects; lets the caller skip the
     * copy/enrich pipeline for unrelated types. */
    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_states.size(); }

private:
    enum Tactic : uint8_t {
        TacticExecution = 1u << 0,
        TacticPersistence = 1u << 1,
        TacticDefenseEvasion = 1u << 2,
        TacticPrivilegeEscalation = 1u << 3,
        TacticCredentialAccess = 1u << 4,
        TacticNetwork = 1u << 5,
    };

    struct PidState {
        uint32_t pid = 0;
        std::string endpoint;
        uint8_t mask = 0;
        std::vector<uint8_t> order;
        uint64_t lastSeen100ns = 0;
    };

    static uint8_t TacticFor(const Event& event);
    void PurgeExpired(uint64_t now100ns);
    void WriteState(Event& event, const PidState& state);

    size_t m_stateCapacity;
    uint64_t m_window100ns;
    uint64_t m_lastPurge100ns = 0;
    std::unordered_map<std::string, PidState> m_states;
};

} // namespace edr

#endif /* EDR_ATTACK_CHAIN_DETECTOR_H */
