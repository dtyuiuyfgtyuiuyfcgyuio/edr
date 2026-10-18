/*
 * pass_the_hash_detector.cpp - See pass_the_hash_detector.h.
 */
#include "pass_the_hash_detector.h"

#include <algorithm>
#include <cctype>
#include <initializer_list>

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

} // namespace

PassTheHashDetector::PassTheHashDetector(bool enabled, uint32_t minScore,
                                         uint32_t dedupWindowSeconds,
                                         size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool PassTheHashDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

bool PassTheHashDetector::AnalyzeCommandLine(const std::string& lower,
                                             Finding* out) const {
    /* mimikatz "sekurlsa::pth /user:... /ntlm:<hash>" is the canonical PTH. */
    if (Contains(lower, "sekurlsa::pth")) {
        *out = Finding{90, "mimikatz_pth", "mimikatz"};
        return true;
    }

    /* Impacket suite: psexec/wmiexec/smbexec/atexec/dcomexec -hashes. */
    if (ContainsAny(lower, {"-hashes", "--hashes"})) {
        if (ContainsAny(lower, {"psexec", "wmiexec", "smbexec", "atexec",
                                "dcomexec", "crackmapexec", " cme "})) {
            *out = Finding{85, "impacket_pth", "impacket"};
            return true;
        }
    }

    /* evil-winrm -H <ntlm hash>. */
    if (Contains(lower, "evil-winrm") || Contains(lower, "evil_winrm")) {
        if (ContainsAny(lower, {"-h ", "-h="})) {
            *out = Finding{85, "evil_winrm_pth", "evil-winrm"};
            return true;
        }
    }

    /* crackmapexec smb -H <hash> / --hashes. */
    if (Contains(lower, "crackmapexec") || Contains(lower, " cme ")) {
        if (ContainsAny(lower, {"-h ", "-h=", "--hashes"})) {
            *out = Finding{80, "crackmapexec_pth", "crackmapexec"};
            return true;
        }
    }

    /* Samba pass-the-hash companion tools. */
    if (ContainsAny(lower, {"pth-winexe", "pth-net", "pth-smbclient",
                            "pth-rpcclient", "pth-wmic", "pth-curl"})) {
        *out = Finding{75, "samba_pth_tool", "samba"};
        return true;
    }

    return false;
}

void PassTheHashDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kPassTheHashScore] = std::to_string(finding.score);
    const std::string verdict =
        finding.score >= 75 ? "MALICIOUS" : "SUSPICIOUS";
    event.fields[field::kPassTheHashVerdict] = verdict;
    event.fields[field::kPassTheHashSignals] = finding.signal;
    if (!finding.tool.empty()) {
        event.fields[field::kPassTheHashTools] = finding.tool;
    }
}

void PassTheHashDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty()) {
        auto imgIt = event.fields.find(field::kImage);
        if (imgIt == event.fields.end()) return;
        text = imgIt->second;
    }
    const std::string lower = ToLowerAscii(text);

    Finding finding;
    if (!AnalyzeCommandLine(lower, &finding)) return;
    if (finding.score < m_minScore) return;

    const uint64_t now = event.ts100ns;
    const std::string key = finding.signal;
    auto it = m_lastAlert.find(key);
    if (it != m_lastAlert.end()) {
        if (m_dedupWindow100ns != 0 && now >= it->second &&
            now - it->second < m_dedupWindow100ns)
            return;
        it->second = now;
    } else {
        if (m_stateCapacity > 0 && m_lastAlert.size() >= m_stateCapacity) {
            m_lastAlert.clear();
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
