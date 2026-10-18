/*
 * dpapi_abuse_detector.cpp - DPAPI credential abuse (T1555), graded.
 */
#include "dpapi_abuse_detector.h"

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

/* Browser credential stores whose decryption hinges on DPAPI (Chrome/
 * Edge "Login Data" + "App Bound"/DPAPI-encrypted key in Local State,
 * Firefox logins.json + key4.db). */
bool BrowserStorePath(const std::string& lower) {
    return ContainsAny(lower, {"login data", "local state",
                               "logins.json", "key4.db"});
}

/* Decryption/unprotect primitives that turn a store blob into
 * plaintext credentials. */
bool DecryptPrimitive(const std::string& lower) {
    return ContainsAny(lower, {"dpapi", "masterkey", "cryptunprotect",
                               "unprotect", "decrypt"});
}

} // namespace

DpapiAbuseDetector::DpapiAbuseDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool DpapiAbuseDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool DpapiAbuseDetector::Analyze(const std::string& lower,
                                 Finding* out) const {
    /* Off-the-shelf DPAPI attack tooling invoked by name: SharpDPAPI /
     * SharpChrome and the mimikatz dpapi:: module family. */
    if (Contains(lower, "sharpdpapi") || Contains(lower, "sharpchrome") ||
        Contains(lower, "dpapi::") || Contains(lower, "::dpapi")) {
        *out = Finding{90, "DPAPI attack tooling invoked"};
        return true;
    }

    /* Masterkey extraction / manual CryptUnprotectData flow: DPAPI
     * plus masterkey or unprotect primitives in one command - the
     * hand-rolled shape of the tooling above. */
    if (Contains(lower, "dpapi") &&
        ContainsAny(lower, {"masterkey", "/password", "sha1",
                            "cryptunprotectedata"})) {
        *out = Finding{85, "DPAPI masterkey flow"};
        return true;
    }
    if ((lower.find("masterkey") != std::string::npos ||
         Contains(lower, "cryptunprotectedata")) &&
        BrowserStorePath(lower)) {
        *out = Finding{85, "Browser store masterkey decryption"};
        return true;
    }

    /* Browser credential store plus a decryption context - Chrome/
     * Edge/Firefox theft with the primitives to actually decrypt. */
    if (BrowserStorePath(lower) && DecryptPrimitive(lower)) {
        *out = Finding{75, "Browser credential store decryption"};
        return true;
    }

    /* Vault enumeration - recon of stored web/Windows credentials. */
    if (Contains(lower, "vaultcmd")) {
        *out = Finding{65, "Credential vault enumerated"};
        return true;
    }

    /* Generic stored-credential listing via cmdkey. */
    if (Contains(lower, "cmdkey") && Contains(lower, "/list")) {
        *out = Finding{60, "Stored credentials listed"};
        return true;
    }

    return false;
}

void DpapiAbuseDetector::Stamp(Event& event, const Finding& finding,
                               const std::string& key) {
    event.fields[field::kDpapiAbuseScore] = std::to_string(finding.score);
    event.fields[field::kDpapiAbuseVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kDpapiAbuseSignals] = finding.signal;
    event.fields[field::kDpapiAbuseText] = key;
}

void DpapiAbuseDetector::Enrich(Event& event) {
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
                "[edr-dpapi-abuse] state capacity %zu reached;"
                " dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
