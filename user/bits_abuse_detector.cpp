/*
 * bits_abuse_detector.cpp - See bits_abuse_detector.h.
 */
#include "bits_abuse_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <vector>

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

std::string Verdict(uint32_t score) {
    if (score >= 75) return "MALICIOUS";
    if (score >= 55) return "SUSPICIOUS";
    return "";
}

template <typename Map>
void EvictOldest(Map& map, size_t capacity) {
    if (map.size() <= capacity) return;
    auto oldest = std::min_element(map.begin(), map.end(),
        [](const auto& left, const auto& right) {
            return left.second.lastSeen100ns < right.second.lastSeen100ns;
        });
    if (oldest != map.end()) map.erase(oldest);
}

} // namespace

BitsAbuseDetector::BitsAbuseDetector(bool enabled, uint32_t windowSeconds,
                                     size_t stateCapacity)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) * kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)) {}

bool BitsAbuseDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_PROCESS_START ||
           type == EDR_EVT_FILE_CREATE ||
           type == EDR_EVT_FILE_READ;
}

bool BitsAbuseDetector::IsBitsTool(const std::string& image) {
    static const std::vector<std::string> kTools = {
        "bitsadmin.exe", "powershell.exe", "pwsh.exe", "cmd.exe"
    };
    const std::string lower = LowerAscii(image);
    for (const std::string& tool : kTools) {
        const size_t n = tool.size();
        if (lower.size() >= n &&
            lower.compare(lower.size() - n, n, tool) == 0) {
            return true;
        }
    }
    return false;
}

bool BitsAbuseDetector::IsExecutablePath(const std::string& path) {
    static const char* kExecExtensions[] = {
        ".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1",
        ".vbs", ".js", ".jar", ".hta", ".vbe", ".wsf", ".wsh"
    };
    const std::string lower = LowerAscii(path);
    for (const char* ext : kExecExtensions) {
        const size_t n = std::strlen(ext);
        if (lower.size() >= n &&
            lower.compare(lower.size() - n, n, ext) == 0) {
            return true;
        }
    }
    return false;
}

bool BitsAbuseDetector::IsTransientPath(const std::string& path) {
    const std::string lower = LowerAscii(path);
    return lower.find("\\temp\\") != std::string::npos ||
           lower.find("\\appdata\\") != std::string::npos ||
           lower.find("\\downloads\\") != std::string::npos ||
           lower.find("\\programdata\\") != std::string::npos ||
           lower.find("\\public\\") != std::string::npos ||
           lower.find("\\windows\\tasks\\") != std::string::npos ||
           lower.find("\\windows\\tracing\\") != std::string::npos;
}

bool BitsAbuseDetector::LooksLikeUrl(const std::string& value) {
    const std::string lower = LowerAscii(value);
    return lower.rfind("http://", 0) == 0 || lower.rfind("https://", 0) == 0 ||
           lower.rfind("ftp://", 0) == 0 || lower.rfind("\\\\", 0) == 0;
}

void BitsAbuseDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_procs.begin(); it != m_procs.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns) {
            it = m_procs.erase(it);
        } else {
            ++it;
        }
    }
}

uint32_t BitsAbuseDetector::ComputeScore(const ProcState& state) const {
    uint32_t score = 0;
    if (state.sawBitsTool) score += 25;
    if (state.sawDownloadJob) score += 20;
    if (state.sawUploadJob) score += 20;
    if (state.sawRemoteUrl) score += 15;
    if (state.sawExecTarget) score += 25;
    /* Download job + remote source + executable landing zone is the full
     * T1197 delivery chain; guarantee MALICIOUS on the complete pattern. */
    if (state.sawDownloadJob && state.sawRemoteUrl && state.sawExecTarget) {
        score += 10;
    }
    return std::min(100u, score);
}

std::string BitsAbuseDetector::SignalList(const ProcState& state) const {
    std::string signals;
    const std::pair<bool, const char*> kFlags[] = {
        {state.sawBitsTool, "bits_tool"},
        {state.sawDownloadJob, "download_job"},
        {state.sawUploadJob, "upload_job"},
        {state.sawRemoteUrl, "remote_url"},
        {state.sawExecTarget, "exec_target"},
    };
    for (const auto& entry : kFlags) {
        if (!entry.first) continue;
        if (!signals.empty()) signals += ",";
        signals += entry.second;
    }
    return signals;
}

std::string BitsAbuseDetector::ToolList(const ProcState& state) const {
    std::string list;
    for (const auto& tool : state.tools) {
        if (!list.empty()) list += ",";
        list += tool;
    }
    return list;
}

std::string BitsAbuseDetector::UrlList(const ProcState& state) const {
    std::string list;
    for (const auto& url : state.urls) {
        if (!list.empty()) list += ",";
        list += url;
    }
    return list;
}

std::string BitsAbuseDetector::TargetList(const ProcState& state) const {
    std::string list;
    for (const auto& target : state.targets) {
        if (!list.empty()) list += ",";
        list += target;
    }
    return list;
}

void BitsAbuseDetector::WriteState(Event& event, const ProcState& state) {
    const uint32_t score = ComputeScore(state);
    event.fields[field::kBitsAbuseScore] = std::to_string(score);
    event.fields[field::kBitsAbuseSignals] = SignalList(state);
    event.fields[field::kBitsAbuseTools] = ToolList(state);
    event.fields[field::kBitsAbuseUrls] = UrlList(state);
    event.fields[field::kBitsAbuseTargets] = TargetList(state);
    event.fields[field::kBitsAbuseWindowSeconds] =
        std::to_string(m_windowSeconds);
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) {
        event.fields[field::kBitsAbuseVerdict] = verdict;
    }
}

void BitsAbuseDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const uint32_t pid = event.pid;
    if (pid == 0) return;

    ProcState& state = m_procs[pid];
    bool changed = false;

    if (event.type == EDR_EVT_PROCESS_START) {
        const std::string image = FieldValue(event, field::kImage);
        const std::string command = FieldValue(event, field::kCommandLine);
        const std::string lowerCommand = LowerAscii(command);

        bool isBitsTool = false;
        if (LowerAscii(image).find("bitsadmin") != std::string::npos) {
            isBitsTool = true;
        } else if ((LowerAscii(image).find("powershell") != std::string::npos ||
                    LowerAscii(image).find("pwsh") != std::string::npos) &&
                   lowerCommand.find("start-bitstransfer") !=
                       std::string::npos) {
            isBitsTool = true;
        }

        if (isBitsTool) {
            state.sawBitsTool = true;
            state.tools.insert(LowerAscii(image).substr(
                LowerAscii(image).find_last_of("\\/") + 1));
            changed = true;
        }

        if (isBitsTool || lowerCommand.find("bitsadmin") != std::string::npos) {
            bool uploadJob =
                lowerCommand.find("/upload") != std::string::npos;
            if (!uploadJob &&
                (lowerCommand.find("/transfer") != std::string::npos ||
                 lowerCommand.find("/create") != std::string::npos ||
                 lowerCommand.find("start-bitstransfer") !=
                     std::string::npos)) {
                state.sawDownloadJob = true;
                changed = true;
            }
            if (uploadJob) {
                state.sawUploadJob = true;
                changed = true;
            }

            /* Extract remote URL / UNC source from the command line. */
            const char* kSchemes[] = { "http://", "https://", "ftp://" };
            for (const char* scheme : kSchemes) {
                size_t pos = lowerCommand.find(scheme);
                while (pos != std::string::npos) {
                    size_t end = command.find_first_of(" \t\"", pos);
                    if (end == std::string::npos) end = command.size();
                    state.urls.insert(command.substr(pos, end - pos));
                    pos = lowerCommand.find(scheme, end);
                }
            }
            if (!state.urls.empty() ||
                lowerCommand.find("\\\\") != std::string::npos) {
                state.sawRemoteUrl = true;
                changed = true;
            }

            /* Last token that looks like a local path is the target. */
            size_t start = command.find_last_of(' ');
            std::string lastToken = start == std::string::npos
                                        ? command
                                        : command.substr(start + 1);
            if (!lastToken.empty() && lastToken.front() == '"') {
                lastToken = lastToken.substr(1);
            }
            if (lastToken.size() > 2 && lastToken[1] == ':' &&
                (IsExecutablePath(lastToken) || IsTransientPath(lastToken))) {
                state.sawExecTarget = true;
                state.targets.insert(lastToken);
                changed = true;
            }
        }
    } else if (event.type == EDR_EVT_FILE_CREATE ||
               event.type == EDR_EVT_FILE_READ) {
        const std::string image = FieldValue(event, field::kImage);
        if (LowerAscii(image).find("bitsadmin") == std::string::npos &&
            !state.sawBitsTool) {
            return;
        }
        const std::string path =
            event.type == EDR_EVT_FILE_CREATE
                ? FieldValue(event, field::kFilePath)
                : FieldValue(event, field::kFilePath);
        if (path.empty()) return;
        if (IsExecutablePath(path) && event.type == EDR_EVT_FILE_CREATE) {
            state.sawExecTarget = true;
            state.targets.insert(path);
            changed = true;
        } else if (LooksLikeUrl(path)) {
            state.urls.insert(path);
            state.sawRemoteUrl = true;
            changed = true;
        }
    }

    if (!changed) return;
    state.lastSeen100ns = now;
    WriteState(event, state);
    EvictOldest(m_procs, m_stateCapacity);
}

} // namespace edr
