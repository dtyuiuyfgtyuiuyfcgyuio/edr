/*
 * data_exfiltration_detector.cpp - See data_exfiltration_detector.h.
 */
#include "data_exfiltration_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>

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

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

bool IsPrivateIp(const std::string& ip) {
    /* 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x, ::1 */
    if (ip.empty()) return true;
    if (ip.substr(0, 3) == "10.") return true;
    if (ip.substr(0, 8) == "192.168.") return true;
    if (ip.substr(0, 4) == "127.") return true;
    if (ip.substr(0, 8) == "169.254.") return true;
    if (ip.substr(0, 4) == "172.") {
        const size_t dot = ip.find('.', 4);
        if (dot != std::string::npos) {
            const int second = std::atoi(ip.c_str() + 4);
            if (second >= 16 && second <= 31) return true;
        }
    }
    if (ip == "::1" || ip == "0:0:0:0:0:0:0:1") return true;
    return false;
}

double ShannonEntropy(const std::string& text) {
    if (text.empty()) return 0.0;
    int counts[256] = {};
    for (unsigned char c : text) counts[c]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] == 0) continue;
        const double p = static_cast<double>(counts[i]) / text.size();
        entropy -= p * std::log2(p);
    }
    return entropy;
}

std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 55) return "SUSPICIOUS";
    return "";
}

} // namespace

DataExfiltrationDetector::DataExfiltrationDetector(
        bool enabled, uint32_t windowSeconds, size_t stateCapacity,
        uint32_t dnsTunnelThreshold)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_dnsTunnelThreshold(dnsTunnelThreshold) {}

bool DataExfiltrationDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_NET_CONNECT ||
           type == EDR_EVT_DNS_QUERY ||
           type == EDR_EVT_FILE_READ;
}

bool DataExfiltrationDetector::IsExternalIp(const std::string& ip) {
    return !IsPrivateIp(ip) && !ip.empty();
}

bool DataExfiltrationDetector::IsHighEntropyDomain(const std::string& domain) {
    /* Subdomain-level DNS tunneling: long, high-entropy leftmost labels */
    const size_t dot = domain.find('.');
    if (dot == std::string::npos) return false;
    const std::string label = domain.substr(0, dot);
    if (label.size() < 20) return false;
    return ShannonEntropy(label) > 3.5;
}

bool DataExfiltrationDetector::IsCloudStorageDomain(
        const std::string& domain) {
    const std::string lower = LowerAscii(domain);
    static const char* kCloudDomains[] = {
        ".s3.amazonaws.com", ".blob.core.windows.net",
        ".storage.googleapis.com", ".dropbox.com",
        ".mega.nz", ".wetransfer.com", ".send-anywhere.com",
        ".filebin.net", ".gofile.io", ".transfer.sh"
    };
    for (const char* d : kCloudDomains) {
        if (lower.find(d) != std::string::npos) return true;
    }
    return false;
}

void DataExfiltrationDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_procs.begin(); it != m_procs.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns) {
            it = m_procs.erase(it);
        } else {
            ++it;
        }
    }
}

uint32_t DataExfiltrationDetector::ComputeScore(
        const ProcState& state) const {
    uint32_t score = 0;
    if (state.outboundConnections >= 5) score += 25;
    else if (state.outboundConnections >= 3) score += 15;
    else if (state.outboundConnections >= 1) score += 5;
    if (state.dnsTunnelQueries >= m_dnsTunnelThreshold) score += 40;
    else if (state.dnsTunnelQueries >= m_dnsTunnelThreshold / 2) score += 20;
    if (state.bulkFileReads >= 10) score += 25;
    else if (state.bulkFileReads >= 3) score += 10;
    /* Bonus for multi-signal correlation */
    int signals = 0;
    if (state.outboundConnections >= 3) ++signals;
    if (state.dnsTunnelQueries >= m_dnsTunnelThreshold / 2) ++signals;
    if (state.bulkFileReads >= 3) ++signals;
    if (signals >= 2) score += 15;
    return std::min(100u, score);
}

std::string DataExfiltrationDetector::SignalList(
        const ProcState& state) const {
    std::string signals;
    if (state.outboundConnections >= 1) {
        if (!signals.empty()) signals += ",";
        signals += "outbound_connections:" +
                   std::to_string(state.outboundConnections);
    }
    if (state.dnsTunnelQueries >= 1) {
        if (!signals.empty()) signals += ",";
        signals += "dns_tunnel_queries:" +
                   std::to_string(state.dnsTunnelQueries);
    }
    if (state.bulkFileReads >= 1) {
        if (!signals.empty()) signals += ",";
        signals += "bulk_file_reads:" +
                   std::to_string(state.bulkFileReads);
    }
    return signals;
}

std::string DataExfiltrationDetector::DestList(
        const ProcState& state) const {
    std::string dests;
    for (const auto& d : state.externalDestinations) {
        if (!dests.empty()) dests += ",";
        dests += d;
        if (dests.size() > 200) break;
    }
    return dests;
}

void DataExfiltrationDetector::WriteState(Event& event,
                                          const ProcState& state) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kDataExfilScore] = std::to_string(score);
    event.fields[field::kDataExfilSignals] = SignalList(state);
    event.fields[field::kDataExfilBytesOut] =
        std::to_string(state.outboundConnections);
    event.fields[field::kDataExfilDestinations] = DestList(state);
    event.fields[field::kDataExfilDnsTunnelQueries] =
        std::to_string(state.dnsTunnelQueries);
    event.fields[field::kDataExfilWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty())
        event.fields[field::kDataExfilVerdict] = verdict;
}

void DataExfiltrationDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    if (event.type == EDR_EVT_NET_CONNECT) {
        const std::string dstIp = FieldValue(event, field::kDstIp);
        if (!IsExternalIp(dstIp)) return;
        ProcState& state = m_procs[event.pid];
        state.outboundConnections++;
        state.externalDestinations.insert(dstIp);
        state.lastSeen100ns = now;
        WriteState(event, state);
        return;
    }

    if (event.type == EDR_EVT_DNS_QUERY) {
        const std::string domain = FieldValue(event, field::kDnsQueryName);
        if (domain.empty()) return;
        const bool highEntropy = IsHighEntropyDomain(domain);
        const bool cloud = IsCloudStorageDomain(domain);
        if (!highEntropy && !cloud) return;
        ProcState& state = m_procs[event.pid];
        if (highEntropy) {
            state.dnsTunnelQueries++;
            /* Track the base domain */
            const size_t dot = domain.find('.');
            if (dot != std::string::npos)
                state.tunnelDomains.insert(domain.substr(dot + 1));
        }
        if (cloud) {
            state.outboundConnections++;
            state.externalDestinations.insert(domain);
        }
        state.lastSeen100ns = now;
        WriteState(event, state);
        return;
    }

    if (event.type == EDR_EVT_FILE_READ) {
        const std::string path = FieldValue(event, field::kFilePath);
        if (path.empty()) return;
        ProcState& state = m_procs[event.pid];
        state.bulkFileReads++;
        state.lastSeen100ns = now;
        /* Only stamp if there are already network indicators */
        if (state.outboundConnections > 0 || state.dnsTunnelQueries > 0) {
            WriteState(event, state);
        }
        return;
    }
}

} // namespace edr
