/*
 * net_discovery_detector.cpp - Network discovery burst detector
 * (T1018 / T1049). See header for the scoring model.
 */
#include "net_discovery_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

std::string LowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

bool Contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

/* Last whitespace-separated token that is not a - or / flag. */
std::string LastNonFlagToken(const std::string& text) {
    std::string token;
    size_t pos = 0;
    while (pos < text.size()) {
        while (pos < text.size() &&
               std::isspace(static_cast<unsigned char>(text[pos])))
            ++pos;
        size_t end = pos;
        while (end < text.size() &&
               !std::isspace(static_cast<unsigned char>(text[end])))
            ++end;
        if (end > pos) {
            const std::string t = text.substr(pos, end - pos);
            if (!t.empty() && t[0] != '-' && t[0] != '/')
                token = t;
        }
        pos = end;
    }
    /* Strip surrounding quotes that command lines often carry. */
    while (!token.empty() &&
           (token.front() == '"' || token.front() == '\''))
        token.erase(token.begin());
    while (!token.empty() &&
           (token.back() == '"' || token.back() == '\''))
        token.pop_back();
    return token;
}

} // namespace

NetDiscoveryDetector::NetDiscoveryDetector(bool enabled, uint32_t minScore,
                                           uint32_t windowSeconds,
                                           uint32_t burstThreshold,
                                           uint32_t dedupWindowSeconds,
                                           size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_burstThreshold(burstThreshold == 0 ? 1 : burstThreshold),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool NetDiscoveryDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool NetDiscoveryDetector::Classify(const std::string& lower,
                                    std::string* category,
                                    std::string* detail,
                                    uint32_t* baseScore) const {
    /* AD reconnaissance: nltest domain queries and domain group enum. */
    if (Contains(lower, "nltest") &&
        (Contains(lower, "/dclist") || Contains(lower, "/domain_trusts"))) {
        *category = "adrecon";
        *detail = Contains(lower, "/dclist") ? "dclist" : "domain_trusts";
        *baseScore = 60;
        return true;
    }
    if (Contains(lower, "net group") &&
        (Contains(lower, "/domain") ||
         Contains(lower, "\"domain computers\""))) {
        *category = "adrecon";
        *detail = "net_group_domain";
        *baseScore = 60;
        return true;
    }

    /* Connection-state enumeration (T1049). */
    if (Contains(lower, "get-nettcpconnection")) {
        *category = "netstat";
        *detail = "get-nettcpconnection";
        *baseScore = 55;
        return true;
    }
    if (Contains(lower, "netstat")) {
        *category = "netstat";
        /* PID-correlating -o is the attacker favorite for mapping C2 /
         * sessions to processes. */
        const bool hasO = Contains(lower, " -o") || Contains(lower, "/o") ||
                          Contains(lower, "-ano") || Contains(lower, "-aon") ||
                          Contains(lower, "-nob") || Contains(lower, "-ob");
        *detail = hasO ? "netstat:o" : "netstat";
        *baseScore = hasO ? 70 : 55;
        return true;
    }

    /* Remote system discovery (T1018). */
    if (Contains(lower, "net view") || Contains(lower, "net.exe view")) {
        *category = "netview";
        const size_t unc = lower.find("\\\\");
        *detail = unc == std::string::npos ? "list" : LastNonFlagToken(lower);
        if (detail->empty()) *detail = "list";
        *baseScore = 55;
        return true;
    }
    if (Contains(lower, "arp -a") || Contains(lower, "arp.exe -a")) {
        *category = "arp";
        *detail = "arp-a";
        *baseScore = 55;
        return true;
    }

    /* Ping: only contributes to sweep bursts, never alerts alone. */
    if (Contains(lower, "ping") && Contains(lower, "-n 1")) {
        *category = "ping";
        *detail = LastNonFlagToken(lower);
        if (detail->empty()) return false;
        *baseScore = 0;
        return true;
    }

    return false;
}

bool NetDiscoveryDetector::Analyze(const Event& event, Finding* out) {
    const std::string text = LowerAscii(
        [&event]() {
            if (event.type == EDR_EVT_POWERSHELL_SCRIPT) {
                auto it = event.fields.find(field::kScriptBlockText);
                if (it != event.fields.end()) return it->second;
                return std::string();
            }
            auto it = event.fields.find(field::kCommandLine);
            if (it != event.fields.end() && !it->second.empty())
                return it->second;
            it = event.fields.find(field::kImage);
            return it == event.fields.end() ? std::string() : it->second;
        }());
    if (text.empty()) return false;

    std::string category, detail;
    uint32_t baseScore = 0;
    if (!Classify(text, &category, &detail, &baseScore)) return false;

    /* Record the detail into the category window and prune expired
     * entries (out-of-order past timestamps are clamped, never borrowed
     * from the future). */
    const uint64_t now = event.ts100ns;
    CategoryState& state = m_categories[category];
    for (auto it = state.details.begin(); it != state.details.end();) {
        if (now >= it->second && m_window100ns != 0 &&
            now - it->second > m_window100ns)
            it = state.details.erase(it);
        else
            ++it;
    }
    auto existing = state.details.find(detail);
    if (existing != state.details.end()) {
        if (now > existing->second) existing->second = now;
    } else {
        if (m_stateCapacity > 0 &&
            state.details.size() >= m_stateCapacity) {
            state.details.clear();
            std::fprintf(stderr,
                "[edr-net-discovery] category %s detail capacity %zu "
                "reached; window reset\n",
                category.c_str(), m_stateCapacity);
        }
        state.details.emplace(detail, now);
    }

    const bool burst = state.details.size() >= m_burstThreshold;
    uint32_t score = baseScore;
    const char* signal = "";
    if (burst) {
        score = 80;
        signal = "network discovery enumeration burst";
    } else if (baseScore >= 70) {
        signal = "connection enumeration with pid correlation";
    } else if (baseScore >= 60) {
        signal = "active directory reconnaissance";
    } else if (baseScore >= 55) {
        signal = "network discovery command";
    }
    if (score == 0) return false; /* burst-only contributors stay silent */

    *out = Finding{score, signal};

    /* Dedup: burst escalations dedup per category, base hits per
     * category+detail pair. */
    const std::string key =
        category + (burst ? "\x1F!burst" : "\x1F" + detail);
    auto it = m_lastAlert.find(key);
    if (it != m_lastAlert.end()) {
        if (m_dedupWindow100ns != 0 && now >= it->second &&
            now - it->second < m_dedupWindow100ns)
            return false;
        it->second = now;
    } else {
        if (m_stateCapacity > 0 && m_lastAlert.size() >= m_stateCapacity) {
            m_lastAlert.clear();
            std::fprintf(stderr,
                "[edr-net-discovery] state capacity %zu reached; dedup "
                "reset\n",
                m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }
    return true;
}

void NetDiscoveryDetector::Stamp(Event& event, const Finding& finding) const {
    event.fields[field::kNetDiscoveryScore] = std::to_string(finding.score);
    event.fields[field::kNetDiscoveryVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kNetDiscoverySignals] = finding.signal;
}

void NetDiscoveryDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    Finding finding;
    if (!Analyze(event, &finding)) return;
    if (finding.score < m_minScore) return;
    Stamp(event, finding);
}

} // namespace edr
