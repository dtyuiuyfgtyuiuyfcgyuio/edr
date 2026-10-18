/*
 * web_exfil_detector.cpp - Exfiltration over web service detector
 * (T1567).
 */
#include "web_exfil_detector.h"

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

std::string Basename(const std::string& path) {
    const size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

bool IsUploadVerb(const std::string& lower) {
    return Contains(lower, "-infile") ||
           Contains(lower, "--data-binary") ||
           Contains(lower, "--data @") ||
           Contains(lower, "--form") ||
           Contains(lower, " -f ") ||
           Contains(lower, " -t ") ||
           Contains(lower, " -t\"") ||
           Contains(lower, "-method post") ||
           Contains(lower, "-method put") ||
           Contains(lower, "-methodpost") ||
           Contains(lower, "method post") ||
           Contains(lower, "method put");
}

} // namespace

WebExfilDetector::WebExfilDetector(
    bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds,
    size_t stateCapacity)
    : m_enabled(enabled), m_minScore(minScore),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond),
      m_stateCapacity(stateCapacity) {}

/* static */
bool WebExfilDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_POWERSHELL_SCRIPT;
}

bool WebExfilDetector::Analyze(const std::string& lower,
                               const std::string& imageLower,
                               Finding* out) const {
    const std::string base = Basename(imageLower);

    const bool rclone =
        base == "rclone.exe" || Contains(lower, "rclone");
    if (rclone &&
        (Contains(lower, " copy") || Contains(lower, " sync") ||
         Contains(lower, " move") || Contains(lower, " copyto") ||
         Contains(lower, " moveto"))) {
        *out = Finding{90, "rclone remote upload"};
        return true;
    }

    if (Contains(lower, "discord.com/api/webhooks") ||
        Contains(lower, "discordapp.com/api/webhooks")) {
        *out = Finding{85, "Discord webhook exfil"};
        return true;
    }

    if (Contains(lower, "api.telegram.org/bot") &&
        (Contains(lower, "senddocument") ||
         Contains(lower, "sendmessage") ||
         Contains(lower, "sendphoto") ||
         Contains(lower, "sendvideo"))) {
        *out = Finding{85, "Telegram bot API exfil"};
        return true;
    }

    if (base == "mega-put.bat" || base == "mega-put.exe" ||
        Contains(lower, "mega-put") ||
        ((Contains(lower, "mega.nz") || Contains(lower, "megacmd") ||
          Contains(lower, "megasync")) &&
         (Contains(lower, " put") || Contains(lower, " copy") ||
          Contains(lower, " upload") || Contains(lower, " put:")))) {
        *out = Finding{80, "MEGA cloud upload"};
        return true;
    }

    if (Contains(lower, "pastebin.com/api") ||
        Contains(lower, "transfer.sh") ||
        Contains(lower, "file.io") ||
        Contains(lower, "gofile.io") ||
        Contains(lower, "anonfiles.com")) {
        *out = Finding{75, "anonymous file-host upload"};
        return true;
    }

    const bool transferBin =
        base == "curl.exe" || Contains(lower, "curl ") ||
        Contains(lower, "curl.exe") ||
        Contains(lower, "invoke-webrequest") ||
        Contains(lower, "invoke-restmethod") ||
        Contains(lower, "wget.exe") || Contains(lower, "wget ");
    if (transferBin && IsUploadVerb(lower) &&
        (Contains(lower, "http://") || Contains(lower, "https://"))) {
        *out = Finding{70, "HTTP POST/PUT file upload"};
        return true;
    }

    return false;
}

void WebExfilDetector::Stamp(Event& event, const Finding& finding,
                             const std::string& key) {
    event.fields[field::kWebExfilScore] = std::to_string(finding.score);
    event.fields[field::kWebExfilVerdict] =
        finding.score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kWebExfilSignals] = finding.signal;
    event.fields[field::kWebExfilText] = key;
}

void WebExfilDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    std::string text;
    auto cmdIt = event.fields.find(field::kCommandLine);
    if (cmdIt != event.fields.end()) text = cmdIt->second;
    if (text.empty() && event.type == EDR_EVT_POWERSHELL_SCRIPT) {
        auto scriptIt = event.fields.find(field::kScriptBlockText);
        if (scriptIt != event.fields.end()) text = scriptIt->second;
    }
    std::string image;
    auto imgIt = event.fields.find(field::kImage);
    if (imgIt != event.fields.end()) image = imgIt->second;
    if (text.empty() && image.empty()) return;

    const std::string combined = ToLowerAscii(image + " " + text);
    const std::string imageLower = ToLowerAscii(image);

    Finding finding;
    if (!Analyze(combined, imageLower, &finding)) return;
    if (finding.score < m_minScore) return;

    const std::string key = combined.substr(0, 160);
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
                "[edr-web-exfil] state capacity %zu reached; "
                "dedup reset\n", m_stateCapacity);
        }
        m_lastAlert.emplace(key, now);
    }

    Stamp(event, finding, key);
}

} // namespace edr
