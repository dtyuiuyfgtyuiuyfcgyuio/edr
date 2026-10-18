/*
 * cloud_metadata_detector.h - Cloud instance metadata service (IMDS)
 * access detector (T1552.005).
 *
 * On a compromised cloud VM the fastest credential-theft primitive is a
 * single unauthenticated HTTP GET to the link-local metadata endpoint,
 * which returns the instance's IAM role credentials or a bearer token.
 * This detector scores the command / script plane that reaches for it:
 *
 *   Command plane (EDR_EVT_PROCESS_START) and PowerShell plane
 *   (EDR_EVT_POWERSHELL_SCRIPT, body ONLY in kScriptBlockText). Text
 *   order: kCommandLine -> (PS_SCRIPT) kScriptBlockText -> kImage.
 *
 * Tiers:
 *   85 imds_link_local     the canonical link-local endpoints:
 *                          169.254.169.254 (AWS / GCP / Azure / OpenStack)
 *                          and fd00:ec2::254 (AWS IMDSv2 IPv6). The IPv4
 *                          needle is octet-bounded, so 169.254.169.2545 or
 *                          169.254.169.2540 (a longer dotted run) stays
 *                          silent.
 *   85 gcp_metadata_host   metadata.google.internal / metadata.goog - GCP
 *                          serves the same token material over a DNS name
 *                          instead of the link-local IP.
 *   80 cloud_metadata_host other providers' metadata hosts:
 *                          metadata.tencentyun.com (Tencent Cloud),
 *                          metadata.azure.com, metadata.oraclecloud.com,
 *                          and 100.100.100.200 (Alibaba Cloud, a
 *                          non-link-local CGNAT address that is IMDS-only
 *                          in practice). The IPv4 needle is octet-bounded
 *                          like the 85 tier.
 *   70 imds_token_shape    the request shapes that only exist to pull a
 *                          metadata token even when the host/IP is elided
 *                          from the command text: the AWS IMDSv2 header
 *                          (x-aws-ec2-metadata-token), the GCP header
 *                          (metadata-flavor), and the Azure IMDS token
 *                          paths (/metadata/identity/oauth2/token,
 *                          /metadata/instance?api-version).
 *
 * Verdict contract: >=75 MALICIOUS, >=55 SUSPICIOUS, below 55 never
 * stamped (the min_score gate runs first; a sub-55 finding early-exits).
 *
 * Dedup: key is the signal (tier) name. The same tier inside the dedup
 * window is suppressed; window expiry or a different tier re-arms.
 * State capacity overflow clears the dedup map (same policy as
 * arp_poison_detector / llmnr_poison_detector).
 *
 * Coexistence: cred_file_hunt (T1552.001) owns on-disk credential files
 * and private_key (T1552.004) owns key material; this detector owns the
 * cloud IMDS credential surface (T1552.005) and does not overlap either.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_CLOUD_METADATA_DETECTOR_H
#define EDR_CLOUD_METADATA_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class CloudMetadataDetector {
public:
    CloudMetadataDetector(bool enabled, uint32_t minScore,
                          uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        std::string indicator;
    };

    bool AnalyzeCommandText(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key (signal) -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_CLOUD_METADATA_DETECTOR_H */
