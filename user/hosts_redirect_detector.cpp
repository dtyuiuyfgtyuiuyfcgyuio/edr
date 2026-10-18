/*
 * hosts_redirect_detector.cpp - hosts-file traffic redirection detector
 * (T1565.001 Stored Data Manipulation; C2 / phishing preparation).
 */
// pi-lens-ignore: clang:pp_file_not_found
#include "hosts_redirect_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace edr {

namespace {

bool Contains(const std::string& value, const char* needle) {
    return value.find(needle) != std::string::npos;
}

bool ContainsAny(const std::string& value,
                 const char* const needles[], size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (Contains(value, needles[i])) return true;
    }
    return false;
}

std::string ToLowerAscii(const std::string& text) {
    std::string out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/* The hosts file path in its common spellings. */
bool IsHostsPath(const std::string& lower) {
    return Contains(lower, "drivers\\etc\\hosts") ||
           Contains(lower, "drivers/etc/hosts");
}

/* Domains whose resolution an attacker commonly pins to break AV /
 * EDR update and telemetry channels. */
constexpr const char* kVendorDomains[] = {
    "definitions.update.microsoft.com", "mp.microsoft.com",
    "amupdatedl.microsoft.com", "avdownload.comodo.com",
    "update.symantec.com", "liveupdate.symantecliveupdate.com",
    "spynet.microsoft.com", "mcafee.com", "virustotal.com",
};

constexpr const char* kAppendVerbs[] = {
    "echo", "add-content", ">>", "out-file -append", "tee-object -append",
    "set-content", "copy ", "xcopy", "attrib ",
};

} // namespace

HostsRedirectDetector::HostsRedirectDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool HostsRedirectDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT ||
           type == EDR_EVT_FILE_INTEGRITY;
}

bool HostsRedirectDetector::Analyze(const std::string& lower,
                                    Finding* out) const {
    if (!IsHostsPath(lower)) return false;

    /* Read-only display of the file never scores. */
    if ((Contains(lower, "type ") || Contains(lower, "get-content")) &&
        !ContainsAny(lower, kAppendVerbs,
                     sizeof(kAppendVerbs) / sizeof(kAppendVerbs[0])))
        return false;

    /* Security-vendor domains pinned to attacker-controlled IPs blind
     * AV/EDR updates - the highest-confidence redirection signal. */
    for (const char* domain : kVendorDomains) {
        if (Contains(lower, domain)) {
            *out = Finding{90, "security vendor domain pinned in hosts"};
            return true;
        }
    }

    /* Appended IP-to-domain mapping: leading octet shape inside the
     * appended text (echo "1.2.3.4 host" >> hosts). */
    const bool appendVerb = ContainsAny(
        lower, kAppendVerbs, sizeof(kAppendVerbs) / sizeof(kAppendVerbs[0]));
    if (appendVerb) {
        /* Find a dotted-quad-looking token followed by a name. */
        for (size_t i = 0; i + 7 < lower.size(); ++i) {
            if (lower[i] == ' ' && lower[i + 1] >= '0' &&
                lower[i + 1] <= '9') {
                size_t j = i + 1;
                int dots = 0, digits = 0;
                while (j < lower.size() &&
                       (lower[j] == '.' || (lower[j] >= '0' &&
                                            lower[j] <= '9'))) {
                    if (lower[j] == '.') ++dots; else ++digits;
                    ++j;
                }
                if (dots == 3 && digits >= 4 && j < lower.size() &&
                    lower[j] == ' ') {
                    *out = Finding{85, "IP-to-domain mapping appended to "
                                       "hosts"};
                    return true;
                }
            }
        }
        *out = Finding{75, "hosts file modified via command line"};
        return true;
    }

    return false;
}

void HostsRedirectDetector::Stamp(Event& event, const Finding& finding,
                                  const std::string& key) {
    event.fields[field::kHostsRedirectScore] = std::to_string(finding.score);
    event.fields[field::kHostsRedirectVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kHostsRedirectSignals] = finding.signal;
    event.fields[field::kHostsRedirectText] = key;
}

void HostsRedirectDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    Finding finding;

    if (event.type == EDR_EVT_FILE_INTEGRITY) {
        auto pathIt = event.fields.find(field::kFimPath);
        if (pathIt == event.fields.end()) return;
        text = pathIt->second;

        /* The FIM watch list carries unrelated files (the shipped config
         * also watches ...\drivers\etc\networks), so the path must be
         * confirmed as the hosts file before attributing a redirect. */
        const std::string lowerPath = ToLowerAscii(text);
        if (!IsHostsPath(lowerPath)) return;

        auto actionIt = event.fields.find(field::kFimAction);
        if (actionIt == event.fields.end()) return;
        const std::string action = ToLowerAscii(actionIt->second);
        if (action != "modified" && action != "removed") return;
        finding.score = action == "removed" ? 80u : 70u;
        finding.signal = action == "removed"
            ? "hosts file deleted"
            : "hosts file modified";
        if (finding.score < m_minScore) return;
        /* Dedup per (action, path): a polling FIM re-report of the same
         * action is suppressed, but modified then removed on the same
         * path is a distinct event and must still stamp. */
        StampDeduped(event, finding,
                     action + "|" + lowerPath.substr(0, 160));
        return;
    }

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

    if (!Analyze(lower, &finding)) return;
    if (finding.score < m_minScore) return;

    StampDeduped(event, finding, lower.substr(0, 160));
}

/* Shared dedup + stamp tail for every plane: a repeated key inside the
 * dedup window is dropped, so a polling FIM/registry collector that
 * re-reports the same artifact cannot re-alert. */
void HostsRedirectDetector::StampDeduped(Event& event, const Finding& finding,
                                         const std::string& key) {
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
                "[edr-hosts-redirect] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
