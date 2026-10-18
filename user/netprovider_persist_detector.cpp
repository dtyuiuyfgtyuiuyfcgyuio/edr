/*
 * netprovider_persist_detector.cpp - See netprovider_persist_detector.h.
 */
#include "netprovider_persist_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <vector>

namespace edr {

namespace {

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

/* Split a registry key path into lowered, hive-agnostic segments
 * ("HKLM\SYSTEM\..." and "\REGISTRY\MACHINE\SYSTEM\..." both end up as
 * [.., system, ..]) so matching never depends on the prefix spelling. */
std::vector<std::string> SplitSegments(const std::string& keyPath) {
    std::vector<std::string> segments;
    std::string current;
    for (const char c : keyPath) {
        if (c == '\\') {
            if (!current.empty()) segments.push_back(ToLowerAscii(current));
            current.clear();
        } else {
            current += c;
        }
    }
    if (!current.empty()) segments.push_back(ToLowerAscii(current));
    return segments;
}

bool HasSegmentPair(const std::vector<std::string>& segments,
                    const char* parent, const char* child) {
    for (size_t i = 0; i + 1 < segments.size(); ++i) {
        if (segments[i] == parent && segments[i + 1] == child) return true;
    }
    return false;
}

bool HasSegment(const std::vector<std::string>& segments, const char* name) {
    for (const auto& segment : segments) {
        if (segment == name) return true;
    }
    return false;
}

/* System-directory ProviderPath data is a legitimate network provider
 * install (LanmanWorkstation writes
 * %SystemRoot%\System32\ntlanman.dll). Covers literal and env-var
 * spellings: '%' is stripped from the lowered copy first, otherwise the
 * env-var forms ("%SystemRoot%\System32\...", "%windir%\system32\...")
 * would never contain the "systemroot\system32" / "windir\system32"
 * needles and every legitimate install would be flagged as an external
 * DLL.
 *
 * A needle hit only whitelists when it is followed by a path separator or
 * the end of the data: "c:\windows\system32malware\evil.dll" contains
 * "windows\system32" but is NOT the system directory and must still be
 * flagged (90 provider_path_external_dll). */
bool ContainsDirNeedle(const std::string& data, const std::string& needle) {
    for (size_t pos = data.find(needle); pos != std::string::npos;
         pos = data.find(needle, pos + 1)) {
        const size_t end = pos + needle.size();
        if (end >= data.size()) return true; /* needle ends the string */
        if (data[end] == '\\') return true;  /* followed by a separator */
    }
    return false;
}

bool IsSystemDirectoryPath(const std::string& lower) {
    std::string data = lower;
    data.erase(std::remove(data.begin(), data.end(), '%'), data.end());
    return ContainsDirNeedle(data, "windows\\system32") ||
           ContainsDirNeedle(data, "windows\\syswow64") ||
           ContainsDirNeedle(data, "systemroot\\system32") ||
           ContainsDirNeedle(data, "systemroot\\syswow64") ||
           ContainsDirNeedle(data, "windir\\system32") ||
           ContainsDirNeedle(data, "windir\\syswow64");
}

} // namespace

NetProviderPersistDetector::NetProviderPersistDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool NetProviderPersistDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_REG_WRITE;
}

bool NetProviderPersistDetector::Analyze(const std::string& regKey,
                                         const std::string& regValue,
                                         Finding* out) const {
    if (regKey.empty()) return false;
    const std::vector<std::string> segments = SplitSegments(regKey);
    const std::string valueLower = ToLowerAscii(regValue);

    /* ...\Control\NetworkProvider\Order: any write (value name arrives as
     * kRegValue in the driver shape, as the last key segment in the
     * snapshot shape) reorders or extends the provider load order. */
    if (HasSegmentPair(segments, "networkprovider", "order")) {
        *out = Finding{85, "provider_order_key_write", regKey};
        return true;
    }

    /* Snapshot shape: ...\Services\<svc>\NetworkProvider\ProviderPath with
     * the DLL path as kRegValue. */
    if (HasSegmentPair(segments, "networkprovider", "providerpath")) {
        const std::string data = valueLower;
        if (data.find('\\') != std::string::npos) {
            if (IsSystemDirectoryPath(data)) return false; /* legit install */
            *out = Finding{90, "provider_path_external_dll", regKey};
            return true;
        }
        /* Path-less data on a ProviderPath value is malformed or hostile;
         * keep the mid-band write signal instead of silently dropping. */
        *out = Finding{85, "provider_path_value_write", regKey};
        return true;
    }

    /* Driver shape: kRegKey ends at ...\NetworkProvider and kRegValue is
     * the value name (no value data in the kernel event). */
    if (HasSegment(segments, "networkprovider") && valueLower == "providerpath") {
        *out = Finding{85, "provider_path_value_write", regKey};
        return true;
    }

    return false;
}

void NetProviderPersistDetector::Stamp(Event& event, const Finding& finding) {
    event.fields[field::kNetProviderPersistScore] =
        std::to_string(finding.score);
    event.fields[field::kNetProviderPersistVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kNetProviderPersistSignals] = finding.signal;
    if (finding.key.size() > 200) {
        event.fields[field::kNetProviderPersistKeys] =
            finding.key.substr(0, 200);
    } else {
        event.fields[field::kNetProviderPersistKeys] = finding.key;
    }
}

void NetProviderPersistDetector::Enrich(Event& event) {
    if (!m_enabled || event.type != EDR_EVT_REG_WRITE) return;

    const std::string regKey = FieldValue(event, field::kRegKey);
    const std::string regValue = FieldValue(event, field::kRegValue);

    Finding finding;
    if (!Analyze(regKey, regValue, &finding)) return;
    if (finding.score < m_minScore) return;
    if (finding.score < 55) return; /* sub-verdict: fully silent */

    const std::string key =
        std::string(finding.signal) + "|" + ToLowerAscii(regKey).substr(0, 160);
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
                "[edr-netprovider-persist] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding);
}

} // namespace edr
