/*
 * network_sniffing_detector.cpp - Network sniffing / capture tool
 * detector (T1040).
 */
#include "network_sniffing_detector.h"

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

/* Packet capture binaries - the tool faces attackers drop first. Note
 * "pcap" itself is deliberately absent: it is a library name that would
 * false-positive on file references (foo.pcap, pcap.h). */
bool IsCaptureTool(const std::string& lower) {
    static const char* const kTools[] = {
        "wireshark", "tshark", "dumpcap", "tcpdump", "windump",
        "ethereal", "netsniff", "msgsnarf", "dsniff", "ettercap",
        "bettercap",
    };
    for (const char* tool : kTools) {
        if (Contains(lower, tool)) return true;
    }
    return false;
}

/* Read-only status queries never score. */
bool IsInspectionOnly(const std::string& lower) {
    if (Contains(lower, "netsh trace show") ||
        Contains(lower, "netsh trace status"))
        return true;
    if (Contains(lower, "pktmon status") || Contains(lower, "pktmon list") ||
        Contains(lower, "pktmon help") || Contains(lower, "pktmon /?"))
        return true;
    return false;
}

} // namespace

NetworkSniffingDetector::NetworkSniffingDetector(
        bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
        size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool NetworkSniffingDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool NetworkSniffingDetector::Analyze(const std::string& lower,
                                      Finding* out) const {
    if (IsInspectionOnly(lower)) return false;

    /* Built-in capture planes. */
    if (Contains(lower, "netsh trace start") ||
        Contains(lower, "netsh.exe trace start")) {
        *out = Finding{85, "netsh trace capture started"};
        return true;
    }
    if (Contains(lower, "pktmon start") ||
        Contains(lower, "pktmon.exe start")) {
        *out = Finding{85, "pktmon capture started"};
        return true;
    }

    /* Third-party capture suites. */
    if (IsCaptureTool(lower)) {
        *out = Finding{80, "packet capture tool invoked"};
        return true;
    }

    /* NPcap / WinPcap driver install (capture prerequisite). */
    if ((Contains(lower, "npcap") || Contains(lower, "winpcap")) &&
        (Contains(lower, "msiexec") || Contains(lower, "pnputil") ||
         Contains(lower, "/i ") || Contains(lower, "-i ") ||
         Contains(lower, "install"))) {
        *out = Finding{75, "packet capture driver install"};
        return true;
    }

    /* PowerShell raw-socket capture (IOControl SIO_RCVALL). */
    if (Contains(lower, "sio_rcvall") ||
        (Contains(lower, "iocontrol") && Contains(lower, "receiveall"))) {
        *out = Finding{80, "raw-socket promiscuous capture"};
        return true;
    }

    /* ETL -> pcap conversion: post-processing of a prior capture. */
    if (Contains(lower, "netsh trace convert") ||
        Contains(lower, "etl2pcapng") || Contains(lower, "etl2pcap")) {
        *out = Finding{60, "capture file conversion"};
        return true;
    }

    return false;
}

void NetworkSniffingDetector::Stamp(Event& event, const Finding& finding,
                                    const std::string& key) {
    event.fields[field::kNetworkSniffingScore] =
        std::to_string(finding.score);
    event.fields[field::kNetworkSniffingVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kNetworkSniffingSignals] = finding.signal;
    event.fields[field::kNetworkSniffingCommand] = key;
}

void NetworkSniffingDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
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
                "[edr-net-sniff] state capacity %zu reached; dedup reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
