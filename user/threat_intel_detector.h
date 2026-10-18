/*
 * threat_intel_detector.h - Generic threat-intelligence indicator matching.
 *
 * Loads an operator-supplied indicator-of-compromise (IoC) feed and scores
 * events that reference a known indicator. This is the general-purpose
 * sibling of SilverFoxDetector: SilverFox is a hard-coded vendor feed with
 * behaviour correlation, whereas this detector accepts an arbitrary feed and
 * matches across every observable surface the agent already collects.
 *
 * Supported indicator types and the event surfaces they match:
 *   sha256      PROCESS_START hashes / IMAGE_LOAD image_checksum+hashes
 *   domain      DNS_QUERY query name (exact or parent-domain suffix)
 *   ipv4/ipv6   NET_CONNECT dst_ip
 *   ipv4_cidr/ipv6_cidr NET_CONNECT dst_ip within a network prefix;
 *                     scored and reported as the ipv4/ipv6 category
 *   cert_sha256 IMAGE_LOAD signer certificate thumbprint
 *
 * Scoring: each indicator type carries a base score reflecting how strong
 * the signal is on its own (a file hash is far less ambiguous than a domain
 * that many tenants share). A host-wide consistency bonus is added when the
 * same process accumulates hits of more than one indicator type, because a
 * single binary/flow matching both a hash and a C2 domain is materially
 * stronger than either hit alone. Score is capped at 100.
 *
 * Thread-safety: no internal synchronization. Only the single EventBus
 * consumer thread calls Enrich (see main.cpp), matching every other detector.
 * Explicit loads/reloads must run before startup or on that consumer thread.
 */
#ifndef EDR_THREAT_INTEL_DETECTOR_H
#define EDR_THREAT_INTEL_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "event_bus.h"

namespace edr {

class ThreatIntelDetector {
public:
    ThreatIntelDetector(bool enabled, uint32_t minScore,
                        uint32_t dedupWindowSeconds, size_t stateCapacity,
                        uint32_t reloadPollSeconds = 0);

    /* Loads the IoC feed. Returns false and fills `error` when the file is
     * missing, malformed, or contains no usable indicators. A failed load
     * preserves the previous validated feed and evidence. With no previous
     * feed the detector is inert. Success clears evidence from the old feed.
     * Files are limited to 4 MiB and must contain at least one indicator. */
    bool LoadIndicators(const std::string& path, std::string& error);

    /* Consumer-thread reload: true means a new validated snapshot was applied.
     * False with an empty error means unchanged; false with an error means the
     * old snapshot was retained. Unchanged invalid content is not reparsed.
     * Enrich polls this on inspected events when reloadPollSeconds is nonzero. */
    bool ReloadIndicatorsIfChanged(std::string& error);

    void Enrich(Event& event);

    /* True only for event types Enrich inspects. */
    static bool Inspects(uint16_t type);

    size_t IndicatorCount() const { return m_indicators.size(); }
    size_t StateCount() const { return m_states.size(); }
    bool Enabled() const { return m_enabled; }
    uint32_t MinScore() const { return m_minScore; }
    const std::string& FeedName() const { return m_feedName; }

private:
    enum class IndicatorType {
        Sha256,
        Domain,
        Ipv4,
        Ipv6,
        CertificateSha256,
    };

    struct Indicator {
        std::string id;
        IndicatorType type = IndicatorType::Sha256;
        std::string value;      /* normalized text, or binary CIDR prefix key */
        bool isCidr = false;
        std::string confidence; /* free-form operator label */
        std::string source;     /* feed / provider attribution */
        std::string threat;     /* family or campaign name, optional */
        int baseScore = 0;
        uint64_t validFrom100ns = 0;  /* zero means no lower bound */
        uint64_t validUntil100ns = 0; /* zero means no upper bound */
        bool revoked = false;

        bool IsActive(uint64_t eventTime100ns) const {
            if (revoked) return false;
            if (eventTime100ns == 0)
                return validFrom100ns == 0 && validUntil100ns == 0;
            return eventTime100ns >= validFrom100ns &&
                (validUntil100ns == 0 || eventTime100ns < validUntil100ns);
        }
    };

    struct ProcessState {
        uint64_t lastSeen100ns = 0;
        uint32_t pid = 0;
        std::string endpointId;
        /* Pointers stay valid until an atomic feed replacement clears states.
         * Retain the indicators themselves so expired evidence can be removed
         * without discarding unrelated live evidence or cached score remnants. */
        std::vector<const Indicator*> evidence;
    };

    void PurgeExpired(uint64_t now100ns);
    bool ApplyIndicators(const std::string& contents, std::string& error);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;
    std::string m_feedName;
    std::string m_feedPath;
    std::string m_seenFingerprint;
    std::string m_seenError;
    std::string m_reloadError;
    uint64_t m_reloadPollMs;
    uint64_t m_lastReloadCheckMs = 0;

    /* Exact-match indices. Values are already normalized to lowercase. */
    std::unordered_map<std::string, const Indicator*> m_byHash;
    std::unordered_map<std::string, const Indicator*> m_byDomain;
    std::unordered_map<std::string, const Indicator*> m_byAddress;
    /* Prefix length + masked network bytes; key length separates families.
     * Lookup is bounded by address width, not by the number of feed ranges. */
    std::unordered_map<std::string, const Indicator*> m_byCidr;
    std::unordered_map<std::string, const Indicator*> m_byCert;

    /* Owning storage; indices above point into this vector. Declared after
     * the indices so addresses stay valid for the object's lifetime. */
    std::vector<Indicator> m_indicators;
    std::unordered_map<std::string, ProcessState> m_states;
};

} // namespace edr

#endif /* EDR_THREAT_INTEL_DETECTOR_H */
