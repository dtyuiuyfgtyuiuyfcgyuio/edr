/*
 * lolbin_chain_detector.cpp - See lolbin_chain_detector.h.
 *
 * Repeated suspicious child launches by the same strong parent identity are
 * correlated over a rolling window. This detector only inspects PROCESS_START
 * events and intentionally focuses on LOLBin/script-host children to keep the
 * signal high-value.
 */
#include "lolbin_chain_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <string>
#include <vector>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string BaseName(const std::string& value) {
    size_t slash = value.find_last_of("\\/");
    return LowerAscii(slash == std::string::npos ? value
                                                 : value.substr(slash + 1));
}

/* A bare PPID/image cannot distinguish a recycled parent. Exact creation
 * identities are provider-neutral; opaque identities are producer-local. */
std::string ParentKey(const Event& event) {
    const std::string identity = LowerAscii(event.parentProcessIdentity);
    if (identity.empty() || identity.size() > 256 ||
        identity.rfind("pid:", 0) == 0 || identity.rfind("wmi/", 0) == 0 ||
        identity.find_first_not_of("0123456789") == std::string::npos) return {};
    const std::string endpoint = LowerAscii(FieldValue(event, field::kEndpointId));
    const std::string scope = std::to_string(endpoint.size()) + ":" + endpoint;
    const size_t at = identity.find('@');
    if (at != std::string::npos && at != 0 &&
        identity.substr(0, at).find_first_not_of("0123456789") == std::string::npos) {
        uint32_t pid = 0;
        uint64_t creation = 0;
        const char* begin = identity.data();
        const auto parsedPid = std::from_chars(begin, begin + at, pid);
        const auto parsedTime = std::from_chars(begin + at + 1,
                                                begin + identity.size(), creation);
        if (parsedPid.ec != std::errc{} || parsedPid.ptr != begin + at ||
            parsedTime.ec != std::errc{} || parsedTime.ptr != begin + identity.size() ||
            pid == 0 || creation == 0 || (event.ppid != 0 && event.ppid != pid)) return {};
        return scope + "|pid:" + std::to_string(pid) + "@" + std::to_string(creation);
    }
    std::string source = event.source;
    if (source.empty()) source = FieldValue(event, field::kSource);
    if (source.empty()) return {};
    source = LowerAscii(source);
    if (source != "sysmon" && source != "etw") return {};
    return scope + "|source:" + std::to_string(source.size()) + ":" + source +
           "|opaque:" + identity;
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

bool IsSuspiciousChild(const std::string& childBase) {
    return childBase == "powershell.exe" || childBase == "pwsh.exe" ||
           childBase == "cmd.exe" || childBase == "wscript.exe" ||
           childBase == "cscript.exe" || childBase == "mshta.exe" ||
           childBase == "rundll32.exe" || childBase == "regsvr32.exe" ||
           childBase == "certutil.exe" || childBase == "bitsadmin.exe" ||
           childBase == "msbuild.exe" || childBase == "installutil.exe" ||
           childBase == "regasm.exe" || childBase == "regsvcs.exe" ||
           childBase == "cmstp.exe" || childBase == "msiexec.exe" ||
           childBase == "ieexec.exe" || childBase == "forfiles.exe" ||
           childBase == "pcalua.exe" || childBase == "presentationhost.exe" ||
           childBase == "jsc.exe" || childBase == "csc.exe" ||
           childBase == "ilasm.exe" || childBase == "syncappvpublishingserver.exe";
}

std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 55) return "SUSPICIOUS";
    return "";
}

template <typename Map>
void EvictOldest(Map& map, size_t capacity) {
    if (map.size() <= capacity) return;
    auto oldest = std::min_element(map.begin(), map.end(),
        [](const auto& left, const auto& right) {
            return left.second.lastSeen100ns < right.second.lastSeen100ns;
        });
    if (oldest != map.end()) map.erase(oldest);
}

} // namespace

LolbinChainDetector::LolbinChainDetector(bool enabled, uint32_t windowSeconds,
                                         size_t stateCapacity,
                                         uint32_t minDistinctChildren)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) * kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minDistinctChildren(std::max<uint32_t>(2, minDistinctChildren)) {}

bool LolbinChainDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

void LolbinChainDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_parents.begin(); it != m_parents.end();) {
        ParentState& state = it->second;
        for (auto child = state.children.begin(); child != state.children.end();) {
            if (now100ns >= child->second.lastSeen100ns &&
                now100ns - child->second.lastSeen100ns > m_window100ns) {
                child = state.children.erase(child);
            } else {
                ++child;
            }
        }
        if (state.children.empty()) {
            it = m_parents.erase(it);
        } else {
            // Allow a new threshold crossing after older children expire.
            state.lastFlaggedCount = std::min(state.lastFlaggedCount,
                static_cast<uint32_t>(state.children.size()));
            ++it;
        }
    }
}

void LolbinChainDetector::WriteState(Event& event, const ParentState& state) {
    std::vector<std::string> children;
    for (const auto& entry : state.children) {
        if (children.size() >= 6) break;
        children.push_back(entry.first);
    }
    std::sort(children.begin(), children.end());

    std::string joined;
    for (const std::string& child : children) {
        if (!joined.empty()) joined += ",";
        joined += child;
    }

    const uint32_t count = static_cast<uint32_t>(state.children.size());
    const uint32_t score = std::min(100u, count * 20u + 15u);
    event.fields[field::kLolbinChainScore] = std::to_string(score);
    event.fields[field::kLolbinChainCount] = std::to_string(count);
    event.fields[field::kLolbinChainChildren] = joined;
    event.fields[field::kLolbinChainWindowSeconds] = std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kLolbinChainVerdict] = verdict;
    }
}

void LolbinChainDetector::Enrich(Event& event) {
    if (!m_enabled || !Inspects(event.type) || event.pid == 0) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string parentBase = BaseName(FieldValue(event, field::kParentImage));
    const std::string childBase = BaseName(FieldValue(event, field::kImage));
    if (parentBase.empty() || childBase.empty() || !IsSuspiciousChild(childBase)) {
        return;
    }

    const std::string key = ParentKey(event);
    if (key.empty()) return;
    const auto parent = m_parents.find(key);
    if (parent != m_parents.end() && now < parent->second.lastSeen100ns &&
        parent->second.lastSeen100ns - now > m_window100ns) return;
    ParentState& state = m_parents[key];
    auto existing = state.children.find(childBase);
    if (existing == state.children.end()) {
        ChildInfo info;
        info.lastSeen100ns = now;
        state.children.emplace(childBase, info);
    } else {
        existing->second.lastSeen100ns = std::max(existing->second.lastSeen100ns, now);
    }
    state.lastSeen100ns = std::max(state.lastSeen100ns, now);

    const uint32_t count = static_cast<uint32_t>(state.children.size());
    if (count >= m_minDistinctChildren && count > state.lastFlaggedCount) {
        state.lastFlaggedCount = count;
        WriteState(event, state);
    }

    EvictOldest(m_parents, m_stateCapacity);
}

} // namespace edr
