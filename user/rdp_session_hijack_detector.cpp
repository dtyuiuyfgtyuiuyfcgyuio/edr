/*
 * rdp_session_hijack_detector.cpp - See rdp_session_hijack_detector.h.
 */
#include "rdp_session_hijack_detector.h"

#include <algorithm>
#include <cctype>

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

std::string BaseNameOf(const std::string& value) {
    const size_t slash = value.find_last_of("\\/");
    return slash == std::string::npos ? value : value.substr(slash + 1);
}

/* Recover the value of a /flag:<value> style argument. The flag (with its
 * trailing ':') is the needle; the value runs from right after it to the
 * next whitespace. An optional '=' separator is also tolerated. */
std::string OptionValue(const std::string& lower, const char* flag) {
    const std::string needle = flag;
    const size_t pos = lower.find(needle);
    if (pos == std::string::npos) return std::string();
    size_t valueStart = pos + needle.size();
    if (valueStart < lower.size() && lower[valueStart] == '=') {
        ++valueStart;
    }
    if (valueStart >= lower.size()) return std::string();
    const size_t end = lower.find_first_of(" \t", valueStart);
    return lower.substr(valueStart,
                        end == std::string::npos
                            ? std::string::npos
                            : end - valueStart);
}

} // namespace

RdpSessionHijackDetector::RdpSessionHijackDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool RdpSessionHijackDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

bool RdpSessionHijackDetector::AnalyzeCommandLine(
    const std::string& lower, Finding* out) const {
    if (Contains(lower, "/password:") || Contains(lower, "-password:")) {
        *out = Finding{100, "tscon_with_password", std::string(),
                       OptionValue(lower, "/dest:")};
        return true;
    }
    if (Contains(lower, "/dest:") || Contains(lower, "-dest:")) {
        *out = Finding{90, "tscon_session_hijack", std::string(),
                       OptionValue(lower, "/dest:")};
        return true;
    }
    *out = Finding{75, "tscon_console_switch", std::string(), std::string()};
    return true;
}

void RdpSessionHijackDetector::Stamp(Event& event,
                                     const Finding& finding) {
    event.fields[field::kRdpSessionHijackScore] =
        std::to_string(finding.score);
    const std::string verdict =
        finding.score >= 75 ? "MALICIOUS" : "SUSPICIOUS";
    event.fields[field::kRdpSessionHijackVerdict] = verdict;
    event.fields[field::kRdpSessionHijackSignals] = finding.signal;
    if (!finding.session.empty()) {
        event.fields[field::kRdpSessionHijackSession] = finding.session;
    }
    if (!finding.dest.empty()) {
        event.fields[field::kRdpSessionHijackDest] = finding.dest;
    }
}

void RdpSessionHijackDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string image;
    auto imgIt = event.fields.find(field::kImage);
    if (imgIt != event.fields.end()) image = imgIt->second;
    if (ToLowerAscii(BaseNameOf(image)) != "tscon.exe") return;

    std::string commandLine;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) commandLine = cmdIt->second;
    const std::string lower = ToLowerAscii(commandLine);

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
