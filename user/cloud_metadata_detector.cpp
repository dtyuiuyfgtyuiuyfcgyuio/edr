/*
 * cloud_metadata_detector.cpp - See cloud_metadata_detector.h.
 */
#include "cloud_metadata_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

/* Octet-bounded IPv4 literal match: a hit only counts when the octet run
 * does not continue on either side, so 169.254.169.2545 and
 * 1169.254.169.254 (longer dotted runs) never match the IMDS address. */
bool HasBoundedIpv4(const std::string& lower, const char* ip) {
    const std::string needle(ip);
    for (size_t pos = lower.find(needle); pos != std::string::npos;
         pos = lower.find(needle, pos + 1)) {
        if (pos > 0) {
            const unsigned char prev =
                static_cast<unsigned char>(lower[pos - 1]);
            if (std::isdigit(prev) || prev == '.') continue;
        }
        const size_t end = pos + needle.size();
        if (end < lower.size()) {
            const unsigned char next =
                static_cast<unsigned char>(lower[end]);
            if (std::isdigit(next) || next == '.') continue;
        }
        return true;
    }
    return false;
}

/* Providers that serve IMDS over a plain DNS host name. */
const char* const kGcpMetadataHosts[] = {
    "metadata.google.internal",
    "metadata.goog",
};

const char* const kOtherMetadataHosts[] = {
    "metadata.tencentyun.com",
    "metadata.azure.com",
    "metadata.oraclecloud.com",
};

/* Request shapes that only exist to pull a metadata token. */
const char* const kTokenShapes[] = {
    "x-aws-ec2-metadata-token",
    "metadata-flavor",
    "/metadata/identity/oauth2/token",
    "/metadata/instance?api-version",
};

} // namespace

CloudMetadataDetector::CloudMetadataDetector(bool enabled, uint32_t minScore,
                                             uint32_t dedupWindowSeconds,
                                             size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool CloudMetadataDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool CloudMetadataDetector::AnalyzeCommandText(const std::string& lower,
                                               Finding* out) const {
    /* Tier 85: link-local IMDS endpoints. A single unauthenticated GET
     * here returns the instance role's credentials. */
    if (HasBoundedIpv4(lower, "169.254.169.254")) {
        *out = Finding{85, "imds_link_local", "169.254.169.254"};
        return true;
    }
    if (Contains(lower, "fd00:ec2::254")) {
        *out = Finding{85, "imds_link_local", "fd00:ec2::254"};
        return true;
    }
    for (const char* host : kGcpMetadataHosts) {
        if (Contains(lower, host)) {
            *out = Finding{85, "gcp_metadata_host", host};
            return true;
        }
    }

    /* Tier 80: other providers' metadata hosts (and the Alibaba IMDS
     * CGNAT address). */
    if (HasBoundedIpv4(lower, "100.100.100.200")) {
        *out = Finding{80, "cloud_metadata_host", "100.100.100.200"};
        return true;
    }
    for (const char* host : kOtherMetadataHosts) {
        if (Contains(lower, host)) {
            *out = Finding{80, "cloud_metadata_host", host};
            return true;
        }
    }

    /* Tier 70: token-pull shapes that survive host elision. */
    for (const char* shape : kTokenShapes) {
        if (Contains(lower, shape)) {
            *out = Finding{70, "imds_token_shape", shape};
            return true;
        }
    }

    return false;
}

void CloudMetadataDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kCloudMetadataScore] = std::to_string(finding.score);
    event.fields[field::kCloudMetadataVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kCloudMetadataSignals] = finding.signal;
    if (!finding.indicator.empty())
        event.fields[field::kCloudMetadataIndicator] = finding.indicator;
}

void CloudMetadataDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        /* Script blocks carry the body in kScriptBlockText, never
         * kCommandLine/kImage (house contract). */
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    if (text.empty()) {
        auto imgIt = event.fields.find(field::kImage);
        if (imgIt == event.fields.end()) return;
        text = imgIt->second;
    }
    if (text.empty()) return;

    Finding finding;
    if (!AnalyzeCommandText(ToLowerAscii(text), &finding)) return;

    if (finding.score < m_minScore) return;
    if (finding.score < 55) return; /* sub-verdict: fully silent */

    const std::string key = finding.signal;
    const uint64_t now = event.ts100ns;
    auto it = m_lastAlert.find(key);
    if (it != m_lastAlert.end()) {
        if (m_dedupWindow100ns != 0 && now >= it->second &&
            now - it->second < m_dedupWindow100ns)
            return;
        it->second = now;
    } else {
        if (m_stateCapacity > 0 && m_lastAlert.size() >= m_stateCapacity) {
            m_lastAlert.clear();
            std::fprintf(stderr,
                "[edr-cloud-metadata] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
