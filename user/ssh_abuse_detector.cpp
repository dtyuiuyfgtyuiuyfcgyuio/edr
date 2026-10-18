/*
 * ssh_abuse_detector.cpp - SSH abuse (T1021.004).
 */
#include "ssh_abuse_detector.h"
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
std::string BaseName(const std::string& p) {
    size_t pos = p.find_last_of("/\\");
    return pos == std::string::npos ? p : p.substr(pos + 1);
}
bool IsSshClient(const std::string& imageLower, const std::string& lower) {
    std::string base = ToLower(BaseName(imageLower));
    // imageLower is already lower, but double-safe
    if (base == "ssh.exe" || base == "plink.exe" || base == "putty.exe" || base == "ssh") return true;
    // fallback: command line mentions the binary name with boundary
    if (Contains(lower, "ssh.exe") || Contains(lower, "plink.exe")) return true;
    return false;
}
} // namespace

SshAbuseDetector::SshAbuseDetector(bool enabled, uint32_t minScore,
                                   uint32_t dedupWindowSeconds, size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) * kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

bool SshAbuseDetector::Inspects(uint16_t type) { return type == EDR_EVT_PROCESS_START; }

bool SshAbuseDetector::Analyze(const std::string& lower, const std::string& imageLower, Finding* out) const {
    if (!IsSshClient(imageLower, lower)) return false;
    // Highest: host key checking disabled + null known hosts
    bool hasStrictNo = Contains(lower, "stricthostkeychecking") && Contains(lower, "no");
    bool hasNullHosts = Contains(lower, "userknownhostsfile") && (Contains(lower, "/dev/null") || Contains(lower, "nul"));
    if (hasStrictNo && hasNullHosts) {
        *out = Finding{90, "ssh host key checking disabled with null known hosts"};
        return true;
    }
    if (hasStrictNo) {
        *out = Finding{85, "ssh host key checking disabled"};
        return true;
    }
    // Identity file
    if (Contains(lower, " -i ") || Contains(lower, " -i\"") || Contains(lower, " -i'")) {
        *out = Finding{80, "ssh with explicit identity file"};
        return true;
    }
    // BatchMode / background -f -N with tunneling options
    if ((Contains(lower, "batchmode") && Contains(lower, "yes")) || (Contains(lower, " -f ") && Contains(lower, " -n ")) || Contains(lower, " -fn ")) {
        *out = Finding{75, "ssh batch/background mode"};
        return true;
    }
    // Nonstandard port
    if (Contains(lower, " -p ")) {
        *out = Finding{60, "ssh with explicit port"};
        return true;
    }
    // Generic remote invocation via ssh client still suspicious at floor
    *out = Finding{55, "ssh client remote invocation"};
    return true;
}

void SshAbuseDetector::Stamp(Event& event, const Finding& f, const std::string& key) {
    event.fields[field::kSshAbuseScore] = std::to_string(f.score);
    event.fields[field::kSshAbuseVerdict] = f.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kSshAbuseSignals] = f.signal;
    event.fields[field::kSshAbuseText] = key;
}

void SshAbuseDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    if (!Inspects(event.type)) return;
    std::string text;
    auto it = event.fields.find(field::kCommandLine);
    if (it != event.fields.end()) text = it->second;
    if (text.empty()) {
        auto i = event.fields.find(field::kImage);
        if (i == event.fields.end()) return;
        text = i->second;
    }
    if (text.empty()) return;
    const std::string lower = ToLower(text);
    std::string image;
    auto imgIt = event.fields.find(field::kImage);
    if (imgIt != event.fields.end()) image = imgIt->second;
    const std::string imageLower = ToLower(image);
    Finding f;
    if (!Analyze(lower, imageLower, &f)) return;
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
            std::fprintf(stderr, "[edr-ssh-abuse] state capacity %zu reached; dedup reset\n", m_stateCapacity);
        }
        m_state.emplace(key, DedupEntry{now, f.score});
    }
    Stamp(event, f, key);
}

} // namespace edr
