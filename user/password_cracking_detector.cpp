/*
 * password_cracking_detector.cpp - See password_cracking_detector.h.
 */
#include "password_cracking_detector.h"

#include <algorithm>
#include <cctype>
#include <initializer_list>

namespace edr {
namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

bool ContainsAny(const std::string& value,
                 std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (Contains(value, needle)) return true;
    }
    return false;
}

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/* Last path component of an image path (case kept; caller lowercases). */
std::string BaseName(const std::string& path) {
    const size_t slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

} // namespace

PasswordCrackingDetector::PasswordCrackingDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool PasswordCrackingDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START;
}

bool PasswordCrackingDetector::Analyze(const std::string& lowerBase,
                                       const std::string& lowerCmd,
                                       Finding* out) const {
    if (lowerBase == "hashcat.exe" || lowerBase == "hashcat" ||
        Contains(lowerCmd, "hashcat")) {
        *out = Finding{90, "hashcat", "hashcat"};
        return true;
    }
    if (lowerBase == "john.exe" || lowerBase == "john" ||
        Contains(lowerCmd, "john-the-ripper") ||
        Contains(lowerCmd, "john --")) {
        *out = Finding{85, "john_the_ripper", "john"};
        return true;
    }
    if (lowerBase == "ophcrack.exe" || lowerBase == "ophcrack" ||
        Contains(lowerCmd, "ophcrack")) {
        *out = Finding{80, "ophcrack", "ophcrack"};
        return true;
    }
    if (lowerBase == "samdump2.exe" || lowerBase == "samdump2" ||
        Contains(lowerCmd, "samdump2")) {
        *out = Finding{75, "samdump2", "samdump2"};
        return true;
    }
    if (lowerBase == "cain.exe" || lowerBase == "cain" ||
        Contains(lowerCmd, "cain.exe")) {
        *out = Finding{75, "cain_abel", "cain"};
        return true;
    }
    if (lowerBase == "fcrackzip.exe" || lowerBase == "fcrackzip" ||
        Contains(lowerCmd, "fcrackzip")) {
        *out = Finding{60, "fcrackzip", "fcrackzip"};
        return true;
    }
    if (lowerBase == "hashid.exe" || lowerBase == "hashid" ||
        lowerBase == "hash-identifier.exe" ||
        lowerBase == "hash-identifier" ||
        Contains(lowerCmd, "hash-identifier")) {
        *out = Finding{55, "hash_identifier", "hashid"};
        return true;
    }
    return false;
}

void PasswordCrackingDetector::Stamp(Event& event,
                                     const Finding& finding) {
    event.fields[field::kPasswordCrackScore] = std::to_string(finding.score);
    const std::string verdict =
        finding.score >= 75 ? "MALICIOUS" : "SUSPICIOUS";
    event.fields[field::kPasswordCrackVerdict] = verdict;
    event.fields[field::kPasswordCrackSignals] = finding.signal;
    if (!finding.tool.empty()) {
        event.fields[field::kPasswordCrackTools] = finding.tool;
    }
}

void PasswordCrackingDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string image;
    auto imgIt = event.fields.find(field::kImage);
    if (imgIt != event.fields.end()) image = imgIt->second;
    std::string command;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) command = cmdIt->second;

    /* Fall back to the image path when no command line was captured. */
    if (command.empty()) command = image;

    const std::string lowerBase = ToLowerAscii(BaseName(image));
    const std::string lowerCmd = ToLowerAscii(command);

    Finding finding;
    if (!Analyze(lowerBase, lowerCmd, &finding)) return;
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
