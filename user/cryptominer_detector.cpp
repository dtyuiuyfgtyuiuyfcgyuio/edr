/*
 * cryptominer_detector.cpp - See cryptominer_detector.h.
 */
#include "cryptominer_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>

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

bool ContainsI(const std::string& haystack, const char* needle) {
    const std::string h = LowerAscii(haystack);
    const std::string n = LowerAscii(needle);
    return h.find(n) != std::string::npos;
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 55) return "SUSPICIOUS";
    return "";
}

} // namespace

CryptominerDetector::CryptominerDetector(bool enabled,
                                         uint32_t windowSeconds,
                                         size_t stateCapacity)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool CryptominerDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_NET_CONNECT ||
           type == EDR_EVT_DNS_QUERY;
}

bool CryptominerDetector::IsKnownMiningPoolDomain(const std::string& domain) {
    const std::string lower = LowerAscii(domain);
    /* Major mining pools and known stratum domains */
    static const char* kPools[] = {
        "ethashpool", "ethermine", "nanopool", "f2pool", "antpool",
        "pool.minexmr", "monero-pool", "xmrpool", "supportxmr",
        "minergate", "hashflare", "nicehash", "miningpoolhub",
        "2miners", "flypool", "dwarfpool", "multipool",
        "zergpool", "hashpool", "luxor.tech", "viabtc",
        "binance.vision", "cruxpool", "beepool", "ezil",
        "herominers", "woolypooly", "kryptex", "prohashing",
        "flexpool", "crystalpool", "hiveon"
    };
    for (const char* pool : kPools) {
        if (lower.find(pool) != std::string::npos) return true;
    }
    /* Generic stratum/xmr patterns */
    if (lower.find("stratum+") != std::string::npos) return true;
    if (lower.find("xmr-pool") != std::string::npos) return true;
    return false;
}

bool CryptominerDetector::IsKnownMinerBinary(const std::string& image) {
    const std::string base = BaseName(image);
    static const char* kMiners[] = {
        "xmrig.exe", "ethminer.exe", "claymore.exe", "PhoenixMiner.exe",
        "nicehashminer.exe", "minergate.exe", "ccminer.exe",
        "ethclaymore.exe", "nbminer.exe", "trex.exe", "lolminer.exe",
        "gminer.exe", "teamredminer.exe", "wildrig.exe", "progpowminer.exe",
        "minerd.exe", "cpuminer.exe", "cgminer.exe", "bfgminer.exe",
        "cast-xmr.exe", "xmr-stak.exe", "cryptonight.exe", "stratum.exe"
    };
    for (const char* miner : kMiners) {
        if (base == miner) return true;
    }
    return false;
}

bool CryptominerDetector::IsStratumPort(const std::string& port) {
    /* Common stratum mining ports */
    return port == "3333" || port == "4444" || port == "5555" ||
           port == "7777" || port == "8888" || port == "14444" ||
           port == "14433" || port == "3357" || port == "3443";
}

void CryptominerDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_procs.begin(); it != m_procs.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns) {
            it = m_procs.erase(it);
        } else {
            ++it;
        }
    }
}

uint32_t CryptominerDetector::ComputeScore(const ProcState& state) const {
    uint32_t score = 0;
    if (state.sawMinerBinary) score += 45;
    if (state.sawPoolDomain) score += 30;
    if (state.sawPoolIp) score += 20;
    if (state.sawStratumPort) score += 25;
    /* Correlation bonus */
    int signals = 0;
    if (state.sawMinerBinary) ++signals;
    if (state.sawPoolDomain) ++signals;
    if (state.sawStratumPort) ++signals;
    if (signals >= 2) score += 15;
    return std::min(100u, score);
}

std::string CryptominerDetector::SignalList(const ProcState& state) const {
    std::string signals;
    const char* names[] = {"miner_binary", "pool_domain", "pool_ip",
                           "stratum_port"};
    const bool flags[] = {state.sawMinerBinary, state.sawPoolDomain,
                          state.sawPoolIp, state.sawStratumPort};
    for (size_t i = 0; i < 4; ++i) {
        if (!flags[i]) continue;
        if (!signals.empty()) signals += ",";
        signals += names[i];
    }
    return signals;
}

std::string CryptominerDetector::PoolDomainList(
        const ProcState& state) const {
    std::string list;
    for (const auto& d : state.poolDomains) {
        if (!list.empty()) list += ",";
        list += d;
        if (list.size() > 200) break;
    }
    return list;
}

std::string CryptominerDetector::PoolIpList(const ProcState& state) const {
    std::string list;
    for (const auto& ip : state.poolIps) {
        if (!list.empty()) list += ",";
        list += ip;
        if (list.size() > 200) break;
    }
    return list;
}

void CryptominerDetector::WriteState(Event& event,
                                     const ProcState& state) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kCryptoMinerScore] = std::to_string(score);
    event.fields[field::kCryptoMinerSignals] = SignalList(state);
    event.fields[field::kCryptoMinerPoolDomains] = PoolDomainList(state);
    event.fields[field::kCryptoMinerPoolIps] = PoolIpList(state);
    event.fields[field::kCryptoMinerWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty())
        event.fields[field::kCryptoMinerVerdict] = verdict;
}

void CryptominerDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    if (event.type == EDR_EVT_PROCESS_START) {
        const std::string image = FieldValue(event, field::kImage);
        if (!IsKnownMinerBinary(image)) return;
        ProcState& state = m_procs[event.pid];
        state.sawMinerBinary = true;
        state.lastSeen100ns = now;
        WriteState(event, state);
        return;
    }

    if (event.type == EDR_EVT_NET_CONNECT) {
        const std::string dstPort = FieldValue(event, field::kDstPort);
        const std::string dstIp = FieldValue(event, field::kDstIp);
        bool interesting = false;
        if (IsStratumPort(dstPort)) interesting = true;
        if (!interesting) {
            /* Check if dst IP is already tracked as a pool IP */
            for (const auto& pair : m_procs) {
                if (pair.second.poolIps.count(dstIp) > 0) {
                    interesting = true;
                    break;
                }
            }
        }
        if (!interesting) return;
        ProcState& state = m_procs[event.pid];
        if (IsStratumPort(dstPort)) state.sawStratumPort = true;
        if (!dstIp.empty()) {
            state.sawPoolIp = true;
            state.poolIps.insert(dstIp);
        }
        state.lastSeen100ns = now;
        WriteState(event, state);
        return;
    }

    if (event.type == EDR_EVT_DNS_QUERY) {
        const std::string domain = FieldValue(event, field::kDnsQueryName);
        if (!IsKnownMiningPoolDomain(domain)) return;
        ProcState& state = m_procs[event.pid];
        state.sawPoolDomain = true;
        state.poolDomains.insert(domain);
        state.lastSeen100ns = now;
        WriteState(event, state);
        return;
    }
}

} // namespace edr
