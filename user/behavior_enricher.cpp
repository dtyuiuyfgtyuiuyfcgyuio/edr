/*
 * behavior_enricher.cpp - See behavior_enricher.h.
 *
 * Scoring (PROCESS_START only): browser parent launching powershell/pwsh +60;
 * parent/child pair outside the static whitelist +25; first sighting of that
 * pair +10; image under a user-writable directory +15. Score caps at 100 and
 * is written as chain_score with comma-joined chain_reasons. The whitelist
 * matrix is allow-list style: a pair listed there contributes nothing.
 *
 * LSASS read bursts: PROCESS_READ events targeting lsass.exe accumulate
 * memory_size per reading pid within a rolling window; once the accumulated
 * bytes reach the threshold the current event receives
 * lsass_read_burst_bytes/count (attributed to the reader pid). A read
 * arriving after the window expired resets that pid's accumulator.
 */
#include "behavior_enricher.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "edr_event.h"

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

std::string BaseName(const std::string& value) {
    size_t slash = value.find_last_of("\\/");
    return LowerAscii(slash == std::string::npos ? value
                                                 : value.substr(slash + 1));
}

bool StartsWith(const std::string& value, const char* prefix) {
    return value.compare(0, std::string(prefix).size(), prefix) == 0;
}

bool ParseUint64(const std::string& text, uint64_t& out) {
    if (text.empty() || text.size() > 20) return false;
    uint64_t value = 0;
    for (unsigned char c : text) {
        if (c < '0' || c > '9') return false;
        if (value > (std::numeric_limits<uint64_t>::max() -
                     static_cast<uint64_t>(c - '0')) / 10)
            return false;
        value = value * 10 + static_cast<uint64_t>(c - '0');
    }
    out = value;
    return true;
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

std::string Join(const std::vector<std::string>& values,
                 const char* separator) {
    std::string result;
    for (const std::string& value : values) {
        if (!result.empty()) result += separator;
        result += value;
    }
    return result;
}

/* User-writable launch locations: Temp, AppData, ProgramData, Downloads,
 * Public. The trailing separator avoids matching names such as "template"
 * or "public.dll" that merely start with the same letters. System paths
 * (e.g. C:\Windows\Temp) are never user-writable. */
bool IsUserWritablePath(const std::string& image) {
    const std::string lower = LowerAscii(image);
    if (lower.find("\\windows\\") != std::string::npos) return false;
    return lower.find("\\temp\\") != std::string::npos ||
           lower.find("\\appdata\\") != std::string::npos ||
           lower.find("\\programdata\\") != std::string::npos ||
           lower.find("\\downloads\\") != std::string::npos ||
           lower.find("\\public\\") != std::string::npos;
}

bool IsBrowserParent(const std::string& parentBase) {
    return parentBase == "chrome.exe" || parentBase == "msedge.exe" ||
           parentBase == "firefox.exe";
}

bool IsPowerShellChild(const std::string& childBase) {
    return childBase == "powershell.exe" || childBase == "pwsh.exe";
}

/* Allow-list parent/child matrix (basenames, case-insensitive). Unlisted
 * pairs are "rare" (pending review). */
bool IsWhitelistedPair(const std::string& parentBase,
                       const std::string& childBase, uint32_t ppid) {
    if (ppid == 4) return true; /* System (pid 4) -> * */
    if (parentBase == "services.exe")
        return StartsWith(childBase, "svchost");
    if (StartsWith(parentBase, "svchost")) return true; /* svchost* -> * */
    if (parentBase == "wininit.exe")
        return childBase == "services.exe" || childBase == "lsass.exe" ||
               childBase == "winlogon.exe";
    if (parentBase == "csrss.exe") return true; /* csrss -> * */
    if (parentBase == "explorer.exe") return true; /* explorer -> * */
    if (parentBase == "chrome.exe") return childBase == "chrome.exe";
    if (parentBase == "msedge.exe") return childBase == "msedge.exe";
    if (parentBase == "firefox.exe") return childBase == "firefox.exe";
    return false;
}

template <typename Key, typename Value>
void EvictOldest(std::unordered_map<Key, Value>& map, size_t capacity) {
    if (map.size() <= capacity) return;
    auto oldest = std::min_element(map.begin(), map.end(),
        [](const auto& left, const auto& right) {
            return left.second.lastSeen100ns < right.second.lastSeen100ns;
        });
    if (oldest != map.end()) map.erase(oldest);
}

} // namespace

BehaviorEnricher::BehaviorEnricher(size_t stateCapacity,
                                   uint32_t windowSeconds,
                                   uint32_t lsassBurstWindowSeconds,
                                   uint64_t lsassBurstThresholdBytes)
    : m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_lsassWindow100ns(static_cast<uint64_t>(lsassBurstWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_lsassThresholdBytes(lsassBurstThresholdBytes) {}

void BehaviorEnricher::PurgeExpired(uint64_t now100ns) {
    /* Lazy sweep: at most once per window. Keeps the per-event hot path
     * O(1) while expiry granularity stays bounded by one window. */
    if (m_lastPurge100ns != 0 &&
        now100ns >= m_lastPurge100ns &&
        now100ns - m_lastPurge100ns <= m_window100ns)
        return;
    m_lastPurge100ns = now100ns;
    for (auto it = m_parentChild.begin(); it != m_parentChild.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns)
            it = m_parentChild.erase(it);
        else
            ++it;
    }
    for (auto it = m_lsassBursts.begin(); it != m_lsassBursts.end();) {
        if (now100ns >= it->second.windowStart100ns &&
            now100ns - it->second.windowStart100ns > m_lsassWindow100ns)
            it = m_lsassBursts.erase(it);
        else
            ++it;
    }
}

void BehaviorEnricher::Enrich(Event& event) {
    const uint64_t now = EventTime(event);
    PurgeExpired(now);
    if (event.type == EDR_EVT_PROCESS_START) {
        EnrichProcessStart(event, now);
    } else if (event.type == EDR_EVT_PROCESS_READ) {
        EnrichLsassRead(event, now);
    }
}

void BehaviorEnricher::EnrichProcessStart(Event& event, uint64_t now100ns) {
    const std::string image = FieldValue(event, field::kImage);
    const std::string parentImage = FieldValue(event, field::kParentImage);
    const std::string childBase = BaseName(image);
    const std::string parentBase = BaseName(parentImage);
    const bool whitelisted =
        IsWhitelistedPair(parentBase, childBase, event.ppid);

    int score = 0;
    std::vector<std::string> reasons;
    if (IsBrowserParent(parentBase) && IsPowerShellChild(childBase)) {
        score += 60;
        reasons.push_back("browser_ps");
    }
    if (!whitelisted) {
        score += 25;
        reasons.push_back("rare_parent_child");
        const std::string combo = parentBase + "\x1f" + childBase;
        auto existing = m_parentChild.find(combo);
        if (existing == m_parentChild.end()) {
            score += 10;
            reasons.push_back("first_seen");
        }
    }
    if (IsUserWritablePath(image)) {
        score += 15;
        reasons.push_back("user_writable_dir");
    }

    /* Only non-whitelisted pairs are tracked: whitelisted pairs never receive
     * the rare/first-seen bonus, so recording them would only waste LRU
     * capacity that rare-pair first-seen memory depends on. */
    if (!whitelisted) {
        const std::string combo = parentBase + "\x1f" + childBase;
        auto entry = m_parentChild.find(combo);
        if (entry == m_parentChild.end()) {
            m_parentChild.emplace(combo, CountEntry{now100ns, 1});
        } else {
            entry->second.lastSeen100ns = now100ns;
            ++entry->second.count;
        }
        EvictOldest(m_parentChild, m_stateCapacity);
    }

    /* House scoring contract: >=55 is the SUSPICIOUS bar, so a sub-55 chain is
     * not a detection and must not be published. Reachable totals are
     * {10,15,25,35,40,50,60,75,90,100}; only the last four clear the bar. A
     * lone rare_parent_child+first_seen pair (35) or a bare user-writable-dir
     * hit (15) is telemetry noise, not an alert. Publishing them would create a
     * chain_score no rule reads (EDR-081 needs >=60, EDR-135 needs >=55). */
    if (score < 55) return;

    event.fields[field::kChainScore] =
        std::to_string(std::min(100, score));
    event.fields[field::kChainReasons] = Join(reasons, ",");
}

void BehaviorEnricher::EnrichLsassRead(Event& event, uint64_t now100ns) {
    if (BaseName(FieldValue(event, field::kTargetImage)) != "lsass.exe")
        return;
    uint64_t size = 0;
    if (!ParseUint64(FieldValue(event, field::kMemorySize), size) ||
        size == 0)
        return;

    /* Per-reader attribution: burst totals must not be shared across pids. */
    BurstEntry& burst = m_lsassBursts[event.pid];
    if (burst.windowStart100ns == 0 || now100ns < burst.windowStart100ns) {
        /* First read for this pid, or out-of-order event older than the
         * window start (timestamp drift): start a fresh window. */
        burst = BurstEntry{now100ns, 0, 0};
    } else if (now100ns - burst.windowStart100ns > m_lsassWindow100ns) {
        burst = BurstEntry{now100ns, 0, 0};
    }
    burst.bytes += size;
    ++burst.count;
    if (burst.bytes >= m_lsassThresholdBytes) {
        event.fields[field::kLsassReadBurstBytes] =
            std::to_string(burst.bytes);
        event.fields[field::kLsassReadBurstCount] =
            std::to_string(burst.count);
    }
}

} // namespace edr
