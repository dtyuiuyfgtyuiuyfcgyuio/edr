/*
 * sip_hijack_detector.cpp - See sip_hijack_detector.h (T1553.003).
 */
#include "sip_hijack_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/* The SIP function keys an attacker repoints. */
constexpr const char* kSipFunctionKeys[] = {
    "cryptsipdllverifyindirectdata",
    "cryptsipdllgetsigneddatamsg",
    "cryptsipdllismyfiletype",
    "cryptsipdllismyfiletype2",
    "cryptsipdllcreateindirectdata",
    "cryptsipdllremovesigneddatamsg",
    "cryptsipdllputsigneddatamsg",
};

/* Trust provider entry points under Providers\Trust. */
constexpr const char* kTrustProviderKeys[] = {
    "\\trust\\finalpolicy", "\\trust\\initialization",
    "\\trust\\certcheck", "\\trust\\signature",
    "\\trust\\cleanuppolicy", "\\trust\\message",
};

bool ContainsAny(const std::string& value, const char* const needles[],
                 size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (Contains(value, needles[i])) return true;
    }
    return false;
}

/* Read-only inspection of the verification configuration. */
bool IsReadOnlyQuery(const std::string& lower) {
    const bool reads = Contains(lower, "reg query") ||
                       Contains(lower, "get-itemproperty") ||
                       Contains(lower, "get-item ") ||
                       Contains(lower, "get-childitem");
    if (!reads) return false;
    return !Contains(lower, "reg add") && !Contains(lower, "set-item") &&
           !Contains(lower, "new-item") && !Contains(lower, "reg delete") &&
           !Contains(lower, "remove-item");
}

} // namespace

SipHijackDetector::SipHijackDetector(bool enabled, uint32_t minScore,
                                     uint32_t dedupWindowSeconds,
                                     size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool SipHijackDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

bool SipHijackDetector::Analyze(const std::string& lower,
                                Finding* out) const {
    if (IsReadOnlyQuery(lower)) return false;

    const bool sipFunction =
        ContainsAny(lower, kSipFunctionKeys,
                    sizeof(kSipFunctionKeys) / sizeof(kSipFunctionKeys[0]));
    if (sipFunction) {
        *out = Finding{90, "SIP verification function repointed"};
        return true;
    }

    if (ContainsAny(lower, kTrustProviderKeys,
                    sizeof(kTrustProviderKeys) /
                    sizeof(kTrustProviderKeys[0]))) {
        *out = Finding{90, "trust provider entry point repointed"};
        return true;
    }

    /* The OID subtree that hosts the SIP registrations. */
    if (Contains(lower, "encodingtype 0") &&
        (Contains(lower, "cryptsipdll") || Contains(lower, "\\oid\\"))) {
        *out = Finding{90, "CryptSIPDll OID registration write"};
        return true;
    }

    /* SIP provider DLL registration through regsvr32: the DLL self-writes
     * the keys above, so the registration itself is the observable. */
    if ((Contains(lower, "regsvr32") || Contains(lower, "regsvc")) &&
        (Contains(lower, "sip") || Contains(lower, "wintrust"))) {
        *out = Finding{75, "SIP provider DLL registration"};
        return true;
    }

    return false;
}

void SipHijackDetector::Stamp(Event& event, const Finding& finding,
                              const std::string& key) {
    event.fields[field::kSipHijackScore] = std::to_string(finding.score);
    event.fields[field::kSipHijackVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kSipHijackSignals] = finding.signal;
    event.fields[field::kSipHijackText] = key;
}

void SipHijackDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    if (event.type == EDR_EVT_REG_WRITE) {
        auto keyIt = event.fields.find(field::kRegKey);
        if (keyIt == event.fields.end()) return;
        text = keyIt->second;
        auto valIt = event.fields.find(field::kRegValue);
        if (valIt != event.fields.end()) {
            if (!text.empty()) text += " ";
            text += valIt->second;
        }
    } else {
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) text = cmdIt->second;
        if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
            auto scriptIt = event.fields.find(field::kScriptBlockText);
            if (scriptIt != event.fields.end()) text = scriptIt->second;
        }
    }
    if (text.empty()) return;

    const std::string lower = ToLowerAscii(text);
    Finding finding;
    if (!Analyze(lower, &finding)) return;
    if (finding.score < m_minScore) return;

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
                "[edr-sip-hijack] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
