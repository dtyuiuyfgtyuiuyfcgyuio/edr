/*
 * reg_modify_detector.cpp - Modify Registry security-control tamper (T1112).
 */
#include "reg_modify_detector.h"

#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <initializer_list>
#include <map>
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

std::string LastPathComponent(const std::string& value) {
    size_t slash = value.find_last_of("\\/");
    return slash == std::string::npos ? value : value.substr(slash + 1);
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

long ParseInt(const std::string& s) {
    if (s.empty()) return -1;
    try {
        size_t pos = 0;
        long v = std::stol(s, &pos);
        if (pos != s.size()) return -1;
        return v;
    } catch (...) {
        return -1;
    }
}

// Describe a monitored security-control value. Returns false if `v` is not
// one of our value names (so it is owned by another detector / not relevant).
bool DescribeValue(const std::string& v, std::string* signal,
                  uint32_t* base, std::string* category) {
    auto set = [&](const char* sig, uint32_t b, const char* cat) {
        *signal = sig; *base = b; *category = cat; return true;
    };
    if (v == "enablelua")
        return set("uac_enablelua", 75u, "uac");
    if (v == "consentpromptbehavioradmin")
        return set("uac_consentpromptbehavioradmin", 70u, "uac");
    if (v == "promptonsecuredesktop")
        return set("uac_promptonsecuredesktop", 70u, "uac");
    if (v == "filteradministratortoken")
        return set("uac_filteradministratortoken", 70u, "uac");
    if (v == "localaccounttokenfilterpolicy")
        return set("uac_localaccounttokenfilterpolicy", 65u, "uac");
    if (v == "lmcompatibilitylevel")
        return set("lsa_lmcompatibilitylevel", 60u, "lsa");
    if (v == "nolmhash")
        return set("lsa_nolmhash", 60u, "lsa");
    if (v == "runasppl")
        return set("lsa_runasppl", 70u, "lsa");
    if (v == "limitblankpassworduse")
        return set("lsa_limitblankpassworduse", 60u, "lsa");
    if (v == "restrictanonymous")
        return set("lsa_restrictanonymous", 60u, "lsa");
    if (v == "disabledomaincreds")
        return set("lsa_disabledomaincreds", 60u, "lsa");
    if (v == "requiresecuritysignature")
        return set("smb_requiresecuritysignature", 55u, "smb");
    if (v == "executionpolicy")
        return set("powershell_executionpolicy", 65u, "powershell");
    if (v == "enablesmartscreen" || v == "smartscreen")
        return set("smartscreen_smartscreen", 55u, "smartscreen");
    return false;
}

bool IsMonitoredValue(const std::string& v) {
    std::string sig; uint32_t base; std::string cat;
    return DescribeValue(v, &sig, &base, &cat);
}

uint32_t BaseForValue(const std::string& v) {
    std::string sig; uint32_t base; std::string cat;
    return DescribeValue(v, &sig, &base, &cat) ? base : 0u;
}

// Decide whether the resolved value + data is an actual downgrade/tamper.
// `hasData` is true only for the snapshot shape (kRegValue carries the data).
// In the driver shape (no data) we trust the value name as the signal.
bool IsTamper(const std::string& v, const std::string& keyPathLower,
              const std::string& dataLower, bool hasData,
              uint32_t* base, std::string* signal) {
    std::string category;
    if (!DescribeValue(v, signal, base, &category)) return false;

    const bool driverNoData = !hasData;
    const bool eq0 = hasData && dataLower == "0";
    const bool eq1 = hasData && dataLower == "1";

    if (v == "enablelua" || v == "consentpromptbehavioradmin" ||
        v == "promptonsecuredesktop" || v == "filteradministratortoken" ||
        v == "nolmhash" || v == "runasppl" ||
        v == "limitblankpassworduse" || v == "restrictanonymous" ||
        v == "requiresecuritysignature") {
        return driverNoData || eq0;
    }
    if (v == "localaccounttokenfilterpolicy" || v == "disabledomaincreds") {
        return driverNoData || eq1;
    }
    if (v == "lmcompatibilitylevel") {
        if (driverNoData) return true;
        long val = ParseInt(dataLower);
        return val >= 0 && val < 3;  // downgrade below NTLMv2
    }
    if (v == "executionpolicy") {
        // Machine-level only: require a PowerShell key path to avoid matching
        // unrelated ExecutionPolicy values and other detectors' territory.
        if (keyPathLower.find("powershell") == std::string::npos) return false;
        return driverNoData ||
               dataLower == "bypass" || dataLower == "unrestricted";
    }
    if (v == "enablesmartscreen" || v == "smartscreen") {
        return driverNoData || eq0 ||
               dataLower == "off" || dataLower == "disable";
    }
    return false;
}

// Resolve the targeted value name + data from a REG event, handling both
// REG_WRITE shapes. Returns false when neither shape yields a monitored value.
bool ResolveTarget(const std::string& keyPath, const std::string& rawValue,
                   bool* hasData, std::string* valueNameLower,
                   std::string* dataLower) {
    const std::string rv = LowerAscii(rawValue);
    const std::string lc = LowerAscii(LastPathComponent(keyPath));
    if (IsMonitoredValue(rv)) {
        // driver/imonitor shape: kRegValue is the value name, no data present
        *valueNameLower = rv;
        *hasData = false;
        *dataLower = "";
        return true;
    }
    if (IsMonitoredValue(lc)) {
        // snapshot shape: kRegValue is the data, value name is last path comp
        *valueNameLower = lc;
        *hasData = true;
        *dataLower = rv;
        return true;
    }
    return false;
}

template <typename Map>
void EvictOldest(Map& map, size_t capacity) {
    if (capacity == 0 || map.size() <= capacity) return;
    auto oldest = std::min_element(map.begin(), map.end(),
        [](const auto& left, const auto& right) {
            return left.second.lastSeen100ns < right.second.lastSeen100ns;
        });
    if (oldest != map.end()) map.erase(oldest);
}

} // namespace

RegModifyDetector::RegModifyDetector(bool enabled, uint32_t minScore,
                                     uint32_t dedupWindowSeconds,
                                     size_t stateCapacity)
    : m_enabled(enabled),
      m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool RegModifyDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_REG_WRITE || type == EDR_EVT_REG_DELETE;
}

void RegModifyDetector::Stamp(Event& event, uint32_t score,
                              const std::vector<std::string>& signals,
                              const std::vector<std::string>& techniques) const {
    event.fields[field::kRegModifyScore] = std::to_string(score);
    event.fields[field::kRegModifyVerdict] =
        score >= 75 ? "malicious" : "suspicious";
    std::string sig;
    for (const auto& s : signals) {
        if (!sig.empty()) sig += ",";
        sig += s;
    }
    event.fields[field::kRegModifySignals] = sig;
    std::string tech;
    for (const auto& t : techniques) {
        if (!tech.empty()) tech += ",";
        tech += t;
    }
    event.fields[field::kRegModifyTechniques] = tech;
}

void RegModifyDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;

    const std::string keyPath = FieldValue(event, field::kRegKey);
    if (keyPath.empty()) return;
    const std::string rawValue = FieldValue(event, field::kRegValue);

    bool hasData = false;
    std::string valueName, data;
    if (!ResolveTarget(keyPath, rawValue, &hasData, &valueName, &data)) return;

    uint32_t base = 0;
    std::string signal;
    const std::string keyPathLower = LowerAscii(keyPath);
    if (!IsTamper(valueName, keyPathLower, data, hasData, &base, &signal))
        return;  // benign data in snapshot shape, or not a tamper -> silent

    std::string host = FieldValue(event, field::kTargetHost);
    if (host.empty()) host = "host";

    const uint64_t now = EventTime(event);

    // ---- breadth state (per host, short window) ----
    HostState& hs = m_hosts[host];
    if (hs.lastSeen100ns != 0 && now < hs.lastSeen100ns) {
        // clock went backwards; treat as current to avoid stall
        hs.lastSeen100ns = now;
    } else {
        hs.lastSeen100ns = now;
    }
    hs.keys[valueName] = now;

    for (auto it = hs.keys.begin(); it != hs.keys.end();) {
        if (now >= it->second && now - it->second > kEpisodeWindow100ns)
            it = hs.keys.erase(it);
        else
            ++it;
    }
    EvictOldest(m_hosts, m_stateCapacity);

    // ---- dedup: do not re-alert the same (host, value) inside the window ----
    const std::string dkey = host + "|" + valueName;
    auto dit = m_lastAlert.find(dkey);
    if (dit != m_lastAlert.end() && m_dedupWindow100ns != 0 &&
        now >= dit->second && now - dit->second < m_dedupWindow100ns) {
        return;  // suppressed
    }
    if (m_stateCapacity > 0 && m_lastAlert.size() >= m_stateCapacity) {
        m_lastAlert.clear();
        std::fprintf(stderr,
            "[reg_modify] dedup state reached capacity %zu; cleared\n",
            m_stateCapacity);
    }
    m_lastAlert[dkey] = now;

    // ---- score: peak base + breadth bonus over distinct keys in window ----
    uint32_t peakBase = 0;
    uint32_t distinct = static_cast<uint32_t>(hs.keys.size());
    for (const auto& kv : hs.keys)
        peakBase = std::max(peakBase, BaseForValue(kv.first));

    uint32_t score = std::min<uint32_t>(
        100u, peakBase + (distinct == 0 ? 0u : (distinct - 1u) * kBreadthStep));

    if (score < m_minScore) return;
    if (score < 55u) return;  // sub-threshold: fully silent

    std::vector<std::string> signals;
    std::vector<std::string> techniques;
    techniques.push_back("T1112");
    for (const auto& kv : hs.keys) {
        std::string sig; uint32_t b; std::string cat;
        if (DescribeValue(kv.first, &sig, &b, &cat)) {
            signals.push_back(sig);
            bool have = false;
            for (const auto& t : techniques)
                if (t == cat) { have = true; break; }
            if (!have) techniques.push_back(cat);
        }
    }
    std::sort(signals.begin(), signals.end());
    std::sort(techniques.begin(), techniques.end());

    Stamp(event, score, signals, techniques);
}

} // namespace edr
