/*
 * cert_abuse_detector.cpp - Certificate trust abuse (T1553.004), graded.
 */
#include "cert_abuse_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

bool ContainsAny(const std::string& value,
                 std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (Contains(value, needle)) return true;
    }
    return false;
}

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/* True when the addstore target names a machine-wide trust store:
 * "Root" / "-root", "AuthRoot", "CA". Lookalike stores such as
 * "Disallowed" are not trust installs. */
bool TrustStoreTarget(const std::string& lower) {
    if (!Contains(lower, "addstore") && !Contains(lower, "import-certificate"))
        return false;
    return Contains(lower, " root") || Contains(lower, "\"root\"") ||
           Contains(lower, "'root'") || Contains(lower, "-root ") ||
           Contains(lower, "\\root") || Contains(lower, "/root") ||
           Contains(lower, "authroot") || Contains(lower, " localmachine");
}

} // namespace

CertAbuseDetector::CertAbuseDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool CertAbuseDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool CertAbuseDetector::Analyze(const std::string& lower,
                                Finding* out) const {
    /* Root trust-store install: makes attacker-controlled CAs trusted
     * for TLS interception and code signing across the machine. */
    if (TrustStoreTarget(lower)) {
        *out = Finding{90, "Root trust store install"};
        return true;
    }

    /* Private-key export pair: PFX export tooling plus an obvious
     * password/export flag - the exfiltration shape for stolen keys.
     * Bare Export-PfxCertificate on its own stays in the creation
     * band below. */
    if ((Contains(lower, "certutil") && Contains(lower, "-exportpfx")) ||
        (Contains(lower, "pvk2pfx") &&
         (Contains(lower, "-po") || Contains(lower, "-pi"))) ||
        (Contains(lower, "export-pfxcertificate") &&
         Contains(lower, "-password"))) {
        *out = Finding{70, "Private-key PFX export"};
        return true;
    }

    /* Self-signed certificate creation - precursor used for signing
     * malicious payloads or staging trust installs. */
    if (Contains(lower, "new-selfsignedcertificate") ||
        (Contains(lower, "makecert") &&
         Contains(lower, "-r"))) {
        *out = Finding{60, "Self-signed certificate created"};
        return true;
    }

    return false;
}

void CertAbuseDetector::Stamp(Event& event, const Finding& finding,
                              const std::string& key) {
    event.fields[field::kCertAbuseScore] = std::to_string(finding.score);
    event.fields[field::kCertAbuseVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kCertAbuseSignals] = finding.signal;
    event.fields[field::kCertAbuseText] = key;
}

void CertAbuseDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        /* Script blocks carry the body in kScriptBlockText, never
         * kCommandLine/kImage. */
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    if (text.empty()) {
        auto imgIt = event.fields.find(field::kImage);
        if (imgIt == event.fields.end()) return;
        text = imgIt->second;
    }
    const std::string lower = ToLowerAscii(text);

    Finding finding;
    if (!Analyze(lower, &finding)) return;
    if (finding.score < m_minScore) return;

    /* Dedup per normalized text prefix. */
    const std::string key = lower.substr(0, 160);
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
                "[edr-cert-abuse] state capacity %zu reached;"
                " dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
