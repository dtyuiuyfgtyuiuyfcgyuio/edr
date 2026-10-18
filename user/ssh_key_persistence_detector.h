/*
 * ssh_key_persistence_detector.h - SSH authorized-keys backdoor
 * detector (T1098.004).
 *
 * Flags command/script activity that installs or replaces SSH public
 * key material to obtain durable access:
 *   - writes into authorized_keys / administrators_authorized_keys
 *     (echo >>, Set-Content, Add-Content, Out-File, tee)         -> 85
 *   - ssh-keygen followed by a copy/install step into .ssh       -> 75
 *   - bare authorized_keys reference combined with a write verb  -> 70
 *   - creation of the .ssh directory ahead of key install        -> 55
 *   - modification of sshd_config to enable pubkey options       -> 65
 *
 * Genuine interactive `ssh <host>` usage and plain ssh-keygen with no
 * follow-up destination are never scored.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_SSH_KEY_PERSISTENCE_DETECTOR_H
#define EDR_SSH_KEY_PERSISTENCE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class SshKeyPersistenceDetector {
public:
    SshKeyPersistenceDetector(bool enabled, uint32_t minScore,
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

#endif /* EDR_SSH_KEY_PERSISTENCE_DETECTOR_H */
