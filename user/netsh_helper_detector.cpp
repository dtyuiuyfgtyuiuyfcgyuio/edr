/*
 * netsh_helper_detector.cpp - Netsh helper-DLL persistence detector
 * (T1546.007).
 */
#include "netsh_helper_detector.h"

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

std::string LastComponent(const std::string& path) {
    const size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

bool IsBlank(const std::string& value) {
    return value.empty() || value == "\"\"" || value == "''";
}

bool IsReadOnlyQuery(const std::string& lower) {
    if (Contains(lower, "netsh show") ||
        Contains(lower, "show helper") ||
        Contains(lower, "reg query") ||
        Contains(lower, "get-itemproperty") ||
        Contains(lower, "get-item ")) {
        return !Contains(lower, "add helper") &&
               !Contains(lower, "reg add") &&
               !Contains(lower, "set-itemproperty");
    }
    return false;
}

bool IsNetshKey(const std::string& lower) {
    return Contains(lower, "\\microsoft\\netsh") ||
           Contains(lower, "software\\microsoft\\netsh") ||
           LastComponent(lower) == "netsh";
}

} // namespace

NetshHelperDetector::NetshHelperDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool NetshHelperDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_REG_WRITE;
}

bool NetshHelperDetector::Analyze(const std::string& lower,
                                  bool registryPlane,
                                  Finding* out) const {
    if (!registryPlane && IsReadOnlyQuery(lower)) return false;

    if (registryPlane) {
        if (IsNetshKey(lower)) {
            *out = Finding{85, "NetSh helper registry write"};
            return true;
        }
        return false;
    }

    if ((Contains(lower, "netsh") || Contains(lower, "netsh.exe")) &&
        Contains(lower, "add helper")) {
        *out = Finding{90, "netsh add helper"};
        return true;
    }
    if (Contains(lower, "reg add") && IsNetshKey(lower)) {
        *out = Finding{85, "NetSh helper reg add"};
        return true;
    }
    return false;
}

void NetshHelperDetector::Stamp(Event& event, const Finding& finding,
                                const std::string& key) {
    event.fields[field::kNetshHelperScore] = std::to_string(finding.score);
    event.fields[field::kNetshHelperVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kNetshHelperSignals] = finding.signal;
    event.fields[field::kNetshHelperText] = key;
}

void NetshHelperDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    bool registryPlane = false;
    if (event.type == EDR_EVT_REG_WRITE) {
        auto keyIt = event.fields.find(field::kRegKey);
        auto valIt = event.fields.find(field::kRegValue);
        if (keyIt != event.fields.end()) text = keyIt->second;
        if (valIt != event.fields.end()) {
            if (!text.empty()) text += " ";
            text += valIt->second;
        }
        if (keyIt != event.fields.end() && valIt != event.fields.end()) {
            const std::string lowerKey = ToLowerAscii(keyIt->second);
            const std::string lowerVal = ToLowerAscii(valIt->second);
            if (IsNetshKey(lowerKey) && IsBlank(lowerVal) &&
                LastComponent(lowerKey) != "netsh" &&
                !Contains(lowerVal, "netsh"))
                return;
        }
        registryPlane = true;
    } else {
        auto cmdIt = event.fields.find(field::kCommandLine);
        if (cmdIt != event.fields.end()) text = cmdIt->second;
        if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
            auto scriptIt = event.fields.find(field::kScriptBlockText);
            if (scriptIt != event.fields.end()) text = scriptIt->second;
        }
        if (text.empty()) {
            auto imgIt = event.fields.find(field::kImage);
            if (imgIt == event.fields.end()) return;
            text = imgIt->second;
        }
    }
    if (text.empty()) return;
    const std::string lower = ToLowerAscii(text);

    Finding finding;
    if (!Analyze(lower, registryPlane, &finding)) return;
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
                "[edr-netsh-helper] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
