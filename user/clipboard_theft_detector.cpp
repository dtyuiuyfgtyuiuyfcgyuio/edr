/* clipboard_theft_detector.cpp - See clipboard_theft_detector.h. */
#include "clipboard_theft_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <limits>
#include <string>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;

std::string FieldValue(const Event& event, const char* name) {
    const auto it = event.fields.find(name);
    return it == event.fields.end() ? std::string() : it->second;
}

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string BaseName(const std::string& value) {
    const size_t slash = value.find_last_of("\\/");
    return LowerAscii(slash == std::string::npos ? value
                                                  : value.substr(slash + 1));
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           static_cast<uint64_t>(now.dwLowDateTime);
}

bool ParseUint32(const std::string& text, uint32_t* out) {
    if (text.empty() || out == nullptr) return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long value = std::strtoul(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != '\0' ||
        value > std::numeric_limits<uint32_t>::max()) return false;
    *out = static_cast<uint32_t>(value);
    return true;
}

void AddSignal(std::string* signals, const char* signal) {
    if (!signals->empty()) signals->append(",");
    signals->append(signal);
}

bool IsTextFormat(const std::string& raw) {
    uint32_t format = 0;
    if (!ParseUint32(raw, &format)) return false;
    return format == 1 || format == 13; /* CF_TEXT / CF_UNICODETEXT */
}

bool IsRoutineReader(const std::string& base) {
    static constexpr const char* kRoutine[] = {
        "explorer.exe", "shellexperiencehost.exe", "searchhost.exe",
        "startmenuexperiencehost.exe", "rdpclip.exe", "dwm.exe",
        "textinputhost.exe", "ctfmon.exe", "winword.exe", "excel.exe",
        "powerpnt.exe", "outlook.exe", "chrome.exe", "msedge.exe",
        "firefox.exe", "teams.exe", "slack.exe"
    };
    for (const char* name : kRoutine) {
        if (base == name) return true;
    }
    return false;
}

bool IsCollectorTool(const std::string& base) {
    static constexpr const char* kTools[] = {
        "mimikatz.exe", "rundll32.exe", "powershell.exe", "pwsh.exe",
        "cmd.exe", "wscript.exe", "cscript.exe", "python.exe",
        "pythonw.exe", "curl.exe", "certutil.exe", "cliplogger.exe",
        "keylogger.exe", "stealer.exe", "infostealer.exe"
    };
    for (const char* name : kTools) {
        if (base == name) return true;
    }
    return false;
}

template <typename Map>
void EvictOldest(Map& map, size_t capacity) {
    while (map.size() > capacity) {
        auto oldest = std::min_element(map.begin(), map.end(),
            [](const auto& left, const auto& right) {
                return left.second.lastSeen100ns < right.second.lastSeen100ns;
            });
        if (oldest == map.end()) break;
        map.erase(oldest);
    }
}

} // namespace

ClipboardTheftDetector::ClipboardTheftDetector(
        bool enabled, uint32_t minScore, uint32_t windowSeconds,
        size_t stateCapacity, uint32_t minReads,
        uint32_t dedupWindowSeconds)
    : m_enabled(enabled),
      m_minScore(std::max<uint32_t>(1, std::min<uint32_t>(100, minScore))),
      m_windowSeconds(std::max<uint32_t>(1, windowSeconds)),
      m_window100ns(static_cast<uint64_t>(std::max<uint32_t>(1, windowSeconds)) *
                    kFiletimeTicksPerSecond),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minReads(std::max<uint32_t>(1, minReads)),
      m_dedupWindow100ns(static_cast<uint64_t>(dedupWindowSeconds) *
                         kFiletimeTicksPerSecond) {}

bool ClipboardTheftDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_CLIPBOARD_ACCESS;
}

void ClipboardTheftDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_states.begin(); it != m_states.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns) {
            it = m_states.erase(it);
        } else {
            ++it;
        }
    }
}

void ClipboardTheftDetector::Enrich(Event& event) {
    if (!m_enabled || event.type != EDR_EVT_CLIPBOARD_ACCESS) return;

    const uint32_t pid = event.pid != 0 ? event.pid : [&]() {
        uint32_t parsed = 0;
        return ParseUint32(FieldValue(event, field::kPid), &parsed) ? parsed : 0;
    }();
    if (pid == 0) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);
    auto stateIt = m_states.find(pid);
    if (stateIt == m_states.end()) {
        if (m_states.size() >= m_stateCapacity)
            EvictOldest(m_states, m_stateCapacity - 1);
        stateIt = m_states.emplace(pid, State{}).first;
    }
    State& state = stateIt->second;
    state.lastSeen100ns = now;
    if (state.accessCount != std::numeric_limits<uint32_t>::max())
        ++state.accessCount;

    const std::string image = BaseName(FieldValue(event, field::kImage));
    const bool text = IsTextFormat(FieldValue(event, field::kClipboardFormat));
    if (text && state.textReadCount != std::numeric_limits<uint32_t>::max())
        ++state.textReadCount;

    std::string signals;
    uint32_t score = 0;
    if (text) {
        score += 20;
        AddSignal(&signals, "text_clipboard_read");
    }
    if (!IsRoutineReader(image)) {
        score += 25;
        AddSignal(&signals, "unusual_reader");
    }
    if (IsCollectorTool(image)) {
        score += 35;
        AddSignal(&signals, "collection_tool_image");
    }
    if (state.textReadCount >= m_minReads) {
        score += 25;
        AddSignal(&signals, "repeated_text_reads");
    }
    if (state.accessCount >= 10) {
        score += 15;
        AddSignal(&signals, "clipboard_access_burst");
    }
    score = std::min<uint32_t>(100, score);
    if (score < m_minScore || signals.empty()) return;
    if (state.lastAlert100ns != 0 && m_dedupWindow100ns != 0 &&
        now >= state.lastAlert100ns &&
        now - state.lastAlert100ns < m_dedupWindow100ns) return;

    event.fields[field::kClipboardTheftScore] = std::to_string(score);
    event.fields[field::kClipboardTheftVerdict] =
        score >= 75 ? "malicious" : "suspicious";
    event.fields[field::kClipboardTheftSignals] = signals;
    event.fields[field::kClipboardTheftAccessCount] =
        std::to_string(state.accessCount);
    event.fields[field::kClipboardTheftTextReadCount] =
        std::to_string(state.textReadCount);
    event.fields[field::kClipboardTheftWindowSeconds] =
        std::to_string(m_windowSeconds);
    state.lastAlert100ns = now;
}

} // namespace edr
