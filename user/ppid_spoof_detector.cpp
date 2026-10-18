/*
 * ppid_spoof_detector.cpp - Parent-PID spoofing (T1134.004).
 */
#include "ppid_spoof_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

std::string LowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

std::string Basename(const std::string& path) {
    const size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

} // namespace

PpidSpoofDetector::PpidSpoofDetector(bool enabled, uint32_t minScore,
                                      uint32_t dedupWindowSeconds,
                                      size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {
    /* Known-good parent matrix for critical Windows binaries. Any parent
     * outside the allow-list for these children is a strong spoof signal.
     * Keys and values are lowercase basenames. */
    auto& svchostParents =
        m_expectedParents["svchost.exe"];
    svchostParents.insert("services.exe");
    svchostParents.insert("wininit.exe");

    auto& lsassParents = m_expectedParents["lsass.exe"];
    lsassParents.insert("winlogon.exe");

    auto& servicesParents = m_expectedParents["services.exe"];
    servicesParents.insert("wininit.exe");

    auto& smssParents = m_expectedParents["smss.exe"];
    smssParents.insert("system");
    smssParents.insert("");

    auto& csrssParents = m_expectedParents["csrss.exe"];
    csrssParents.insert("smss.exe");

    auto& wininitParents = m_expectedParents["wininit.exe"];
    wininitParents.insert("smss.exe");

    auto& winlogonParents = m_expectedParents["winlogon.exe"];
    winlogonParents.insert("services.exe");
}

/* static */
bool PpidSpoofDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

bool PpidSpoofDetector::Analyze(const std::string& rawParent,
                                 const std::string& rawChild, uint32_t ppid,
                                 Finding* out) const {
    if (!rawChild.empty()) {
        const std::string childBase = LowerAscii(Basename(rawChild));

        /* Signal 1: critical system binary with unexpected parent. */
        auto expectedIt = m_expectedParents.find(childBase);
        if (expectedIt != m_expectedParents.end() && !rawParent.empty()) {
            const std::string parentBase = LowerAscii(Basename(rawParent));
            if (expectedIt->second.count(parentBase) == 0) {
                *out = Finding{90, "system binary spawned by unexpected parent"};
                return true;
            }
        }

    }

    /* Signal 3: user-mode process claiming PID 0 or PID 4 as parent. */
    if (ppid <= 4 && !rawParent.empty()) {
        const std::string childBase = LowerAscii(Basename(rawChild));
        static const char* kKernelBinaries[] = {
            "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "svchost.exe"};
        bool isKnownKernel = false;
        for (const char* kb : kKernelBinaries) {
            if (childBase == kb) { isKnownKernel = true; break; }
        }
        if (!isKnownKernel) {
            *out = Finding{60, "user-mode process with kernel pid parent"};
            return true;
        }
    }

    return false;
}

void PpidSpoofDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kPpidSpoofScore] = std::to_string(finding.score);
    event.fields[field::kPpidSpoofVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kPpidSpoofSignals] = finding.signal;
}

void PpidSpoofDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    auto imageIt = event.fields.find(field::kImage);
    auto parentImageIt = event.fields.find(field::kParentImage);
    const std::string childImage =
        imageIt != event.fields.end() ? imageIt->second : "";
    const std::string parentImage =
        parentImageIt != event.fields.end() ? parentImageIt->second : "";

    Finding finding;
    if (!Analyze(parentImage, childImage, event.ppid, &finding)) return;
    if (finding.score < m_minScore) return;

    const std::string key = LowerAscii(Basename(parentImage)) + "\x1F" +
                            LowerAscii(Basename(childImage));
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
                "[edr-ppid-spoof] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
