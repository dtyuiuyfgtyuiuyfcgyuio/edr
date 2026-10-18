/*
 * kerberoast_detector.h - Kerberoasting service-ticket burst detector.
 *
 * Correlates successful Security 4769 RC4-HMAC TGS requests by source IP and
 * requester. A request is stamped when the requester reaches a configured
 * number of distinct eligible service principals in the rolling window.
 * Standalone krbtgt and machine-account-form ServiceName values are
 * excluded. Ordinary class/instance SPNs (HOST/server, cifs/server, ...)
 * do not reveal their backing account type and remain eligible.
 * Requester count, per-requester service count, output summaries, and alert
 * frequency are all bounded. Source timestamps must be monotonic per
 * requester key; rollback events are rejected before mutation.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_KERBEROAST_DETECTOR_H
#define EDR_KERBEROAST_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class KerberoastDetector {
public:
    /**
     * Constructs a detector with explicit, bounded correlation parameters.
     *
     * @param enabled Whether Enrich inspects events. Disabled detectors
     *     leave events and internal state untouched.
     * @param windowSeconds Rolling source-time window for 4769 requests.
     * @param stateCapacity Maximum number of requester keys retained.
     * @param minServiceCount Distinct eligible services required to stamp.
     * @param dedupSeconds Alert cooldown. Zero disables cooldown.
     * @param maxServicesPerRequester Per-requester service-map cap.
     */
    KerberoastDetector(bool enabled, uint32_t windowSeconds,
                       size_t stateCapacity, uint32_t minServiceCount,
                       uint32_t dedupSeconds,
                       size_t maxServicesPerRequester);

    /**
     * Enriches eligible TGS_REQUEST events with kerberoast_* fields when
     * the distinct-service threshold is met or evidence escalates.
     *
     * @param event Event mutated in place. Ineligible events are unchanged.
     */
    void Enrich(Event& event);

    /**
     * Reports whether Enrich inspects the given normalized event type.
     *
     * @param type EDR event type from edr_event.h.
     * @returns true only for EDR_EVT_LOGON.
     */
    static bool Inspects(uint16_t type);

    /**
     * @returns Number of retained requester keys. For tests only.
     */
    size_t StateCount() const { return m_requesters.size(); }

    /**
     * Counts retained services for a requester after IP and account
     * canonicalization.
     *
     * @param sourceIp Raw or already-normalized source address.
     * @param domain Target domain / realm from the event.
     * @param requester Target user / UPN from the event.
     * @returns Distinct service count, or 0 when the key is rejected or absent.
     */
    size_t ServiceCount(const std::string& sourceIp,
                        const std::string& domain,
                        const std::string& requester) const;

private:
    struct RequesterState {
        std::unordered_map<std::string, uint64_t> services;
        size_t lastAlertedServiceCount = 0;
        uint64_t suppressUntil100ns = 0;
        uint64_t lastSeen100ns = 0;
        uint64_t lastTouchedSequence = 0;
        std::string displayRequester;
    };

    void PruneServices(RequesterState& state, uint64_t now100ns) const;
    void WriteState(Event& event, const std::string& sourceIp,
                    const RequesterState& state) const;

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minServiceCount;
    uint64_t m_dedup100ns;
    size_t m_maxServicesPerRequester;
    uint64_t m_touchSequence = 0;
    std::unordered_map<std::string, RequesterState> m_requesters;
};

} // namespace edr

#endif /* EDR_KERBEROAST_DETECTOR_H */
