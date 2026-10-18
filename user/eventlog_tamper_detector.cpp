/*
 * eventlog_tamper_detector.cpp - Windows event log tampering (T1070.001/T1562.002).
 */
#include "eventlog_tamper_detector.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
namespace edr {
namespace {
bool Contains(const std::string& h, const char* n) { return h.find(n) != std::string::npos; }
std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}
} // namespace

EventlogTamperDetector::EventlogTamperDetector(bool enabled, uint32_t minScore,
                                               uint32_t dedupWindowSeconds, size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) * kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

bool EventlogTamperDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START || type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool EventlogTamperDetector::Analyze(const std::string& lower, Finding* out) const {
    // Security log clear is highest confidence weaponization: wevtutil cl security / clear-eventlog security
    bool hasWevtutil = Contains(lower, "wevtutil ");
    bool hasWevtutilExe = Contains(lower, "wevtutil.exe");
    bool wevt = hasWevtutil || hasWevtutilExe;
    bool wevtCl = wevt && Contains(lower, " cl ");
    bool wevtClearSecurity = wevtCl && Contains(lower, "security");
    if (wevtClearSecurity) {
        *out = Finding{90, "security log cleared via wevtutil"};
        return true;
    }
    // PowerShell Clear-EventLog targeting Security
    if (Contains(lower, "clear-eventlog") && Contains(lower, "security")) {
        *out = Finding{90, "security log cleared via Clear-EventLog"};
        return true;
    }
    // Disable channel: wevtutil sl <channel> /e:false
    if (wevt && Contains(lower, " sl ") && Contains(lower, "/e:false")) {
        *out = Finding{85, "event channel disabled via wevtutil sl /e:false"};
        return true;
    }
    // auditpol /clear wipes audit policy
    if (Contains(lower, "auditpol ") && Contains(lower, "/clear")) {
        *out = Finding{80, "audit policy cleared via auditpol"};
        return true;
    }
    // Generic log clear: wevtutil cl <any>, Clear-EventLog, Remove-EventLog
    if (wevtCl) {
        *out = Finding{75, "event log cleared via wevtutil cl"};
        return true;
    }
    if (Contains(lower, "clear-eventlog")) {
        *out = Finding{75, "event log cleared via Clear-EventLog"};
        return true;
    }
    if (Contains(lower, "remove-eventlog")) {
        *out = Finding{75, "event log removed via Remove-EventLog"};
        return true;
    }
    // Enumeration / query is lowest suspicious tier (recon before tamper)
    if (wevt && (Contains(lower, " gl ") || Contains(lower, " gli ") || Contains(lower, " gli") || Contains(lower, " get-log "))) {
        *out = Finding{55, "event log enumerated via wevtutil"};
        return true;
    }
    // wevtutil without explicit subcommand but with e:false still counts as disable
    if (wevt && Contains(lower, "/e:false")) {
        *out = Finding{85, "event channel disabled"};
        return true;
    }
    return false;
}

void EventlogTamperDetector::Stamp(Event& event, const Finding& f, const std::string& key) {
    event.fields[field::kEventlogTamperScore] = std::to_string(f.score);
    event.fields[field::kEventlogTamperVerdict] = f.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kEventlogTamperSignals] = f.signal;
    event.fields[field::kEventlogTamperText] = key;
}

void EventlogTamperDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;
    std::string text;
    auto it = event.fields.find(field::kCommandLine);
    if (it != event.fields.end()) text = it->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        auto s = event.fields.find(field::kScriptBlockText);
        if (s != event.fields.end()) text = s->second;
    }
    if (text.empty()) {
        auto i = event.fields.find(field::kImage);
        if (i == event.fields.end()) return;
        text = i->second;
    }
    if (text.empty()) return;
    const std::string lower = ToLower(text);
    Finding f;
    if (!Analyze(lower, &f)) return;
    if (f.score < m_minScore) return;
    if (f.score < 55) return;
    const std::string key = lower.substr(0, std::min<size_t>(lower.size(), 160));
    const uint64_t now = event.ts100ns;
    auto found = m_state.find(key);
    if (found != m_state.end()) {
        bool inCooldown = m_dedupWindow100ns != 0 && now >= found->second.ts100ns && now - found->second.ts100ns < m_dedupWindow100ns;
        bool widened = f.score > found->second.score;
        if (inCooldown && !widened) return;
        found->second.ts100ns = now;
        found->second.score = std::max(found->second.score, f.score);
    } else {
        if (m_stateCapacity > 0 && m_state.size() >= m_stateCapacity) {
            m_state.clear();
            std::fprintf(stderr, "[edr-eventlog-tamper] state capacity %zu reached; dedup reset\n", m_stateCapacity);
        }
        m_state.emplace(key, DedupEntry{now, f.score});
    }
    Stamp(event, f, key);
}

} // namespace edr
