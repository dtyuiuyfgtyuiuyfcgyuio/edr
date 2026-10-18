/*
 * persistence_chain_detector.h - Multi-mechanism persistence chain detector.
 *
 * Correlates persistence-write events per (pid, image basename) actor key
 * into a rolling window of distinct persistence mechanisms. When at least
 * minMechanisms distinct mechanisms are observed within windowSeconds, the
 * current event is stamped with persist_chain_score /
 * persist_chain_mechanisms / persist_chain_count / persist_chain_window_seconds.
 * State is a bounded, time-expiring map; expired mechanisms are swept lazily
 * on every Enrich and a key whose mechanisms all expire is dropped so its
 * count resets. The stamp is re-emitted when the mechanism count grows
 * (escalation re-alert), so an actor adding a fourth mechanism after a
 * third is reported again. Enrichment is best-effort and never throws.
 *
 * Recognized mechanisms (derived from fields, no new collectors):
 *   - run_key:         REG_WRITE under CurrentVersion\\Run
 *   - ifeo_debugger:   REG_WRITE under Image File Execution Options
 *   - winlogon:        REG_WRITE under Winlogon (Shell/Userinit)
 *   - appinit_dlls:    REG_WRITE to AppInit_DLLs
 *   - lsa_packages:    REG_WRITE under Control\\Lsa (SecurityPackages)
 *   - com_inproc:      REG_WRITE under CLSID\\InProcServer32
 *   - wdigest:         REG_WRITE under SecurityProviders\\WDigest
 *   - portproxy:       REG_WRITE under Services\\PortProxy
 *   - appcert_dlls:    REG_WRITE under Session Manager\\AppCertDlls
 *   - silent_process_exit: REG_WRITE under SilentProcessExit
 *   - scheduled_task:  TASK_SCHEDULER registration/update
 *   - service:         SERVICE_CHANGE with service_action=added
 *   - startup_folder:  FILE_CREATE under a Startup folder
 *   - wmi_subscription: WMI_EVENT 5859/5861 permanent subscription
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_PERSISTENCE_CHAIN_DETECTOR_H
#define EDR_PERSISTENCE_CHAIN_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PersistenceChainDetector {
public:
    PersistenceChainDetector(bool enabled, uint32_t windowSeconds,
                             size_t stateCapacity, uint32_t minMechanisms);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects; lets the caller skip the
     * copy/enrich pipeline for unrelated types. */
    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_keys.size(); }

private:
    struct MechanismInfo {
        uint64_t lastSeen100ns = 0;
    };

    struct KeyState {
        std::unordered_map<std::string, MechanismInfo> mechanisms;
        uint32_t lastFlaggedCount = 0;
        uint64_t lastSeen100ns = 0;
    };

    void PurgeExpired(uint64_t now100ns);
    void WriteState(Event& event, const KeyState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minMechanisms;
    std::unordered_map<std::string, KeyState> m_keys;
};

} // namespace edr

#endif /* EDR_PERSISTENCE_CHAIN_DETECTOR_H */
