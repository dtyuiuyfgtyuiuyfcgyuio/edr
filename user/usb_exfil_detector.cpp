/*
 * usb_exfil_detector.cpp - See usb_exfil_detector.h.
 */
#include "usb_exfil_detector.h"

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
    while (map.size() > capacity) {
        auto oldest = std::min_element(map.begin(), map.end(),
            [](const auto& left, const auto& right) {
                return left.second.lastSeen100ns <
                       right.second.lastSeen100ns;
            });
        if (oldest == map.end()) break;
        map.erase(oldest);
    }
}

} // namespace

UsbExfilDetector::UsbExfilDetector(bool enabled, uint32_t windowSeconds,
                                   size_t stateCapacity,
                                   uint32_t minFileCount,
                                   uint32_t dedupSeconds)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minFileCount(std::max<uint32_t>(2, minFileCount)),
      m_dedup100ns(static_cast<uint64_t>(dedupSeconds) *
                   kFiletimeTicksPerSecond),
      m_dedupSeconds(dedupSeconds) {}

bool UsbExfilDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_USB_DEVICE || type == EDR_EVT_FILE_CREATE ||
           type == EDR_EVT_FILE_RENAME;
}

std::string UsbExfilDetector::DriveLetterOf(const std::string& path) {
    if (path.size() < 3 || path[1] != ':') return "";
    std::string drive = path.substr(0, 2);
    drive[0] = static_cast<char>(
        std::toupper(static_cast<unsigned char>(drive[0])));
    return drive;
}

bool UsbExfilDetector::IsSensitiveExtension(const std::string& raw) const {
    const std::string path = LowerAscii(raw);
    size_t dot = path.find_last_of('.');
    if (dot == std::string::npos) return false;
    const std::string ext = path.substr(dot + 1);
    static const char* const kExtensions[] = {
        "doc",  "docx", "xls",  "xlsx", "ppt",  "pptx", "pdf",
        "csv",  "pst",  "ost",  "eml",  "db",   "sql",  "kdbx",
        "pem",  "pfx",  "key",  "wallet", "rdp",
    };
    for (const char* candidate : kExtensions) {
        if (ext == candidate) return true;
    }
    return false;
}

void UsbExfilDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_drives.begin(); it != m_drives.end();) {
        DriveState& state = it->second;
        for (auto file = state.files.begin(); file != state.files.end();) {
            if (now100ns >= file->second &&
                now100ns - file->second > m_window100ns) {
                file = state.files.erase(file);
            } else {
                ++file;
            }
        }
        if (state.files.empty()) {
            it = m_drives.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = m_removable.begin(); it != m_removable.end();) {
        if (now100ns >= it->second &&
            now100ns - it->second > m_window100ns) {
            it = m_removable.erase(it);
        } else {
            ++it;
        }
    }
}

void UsbExfilDetector::WriteState(Event& event, const DriveState& state,
                                  const std::string& drive, uint32_t count,
                                  uint32_t sensitiveCount) const {
    uint32_t score = 0;
    if (sensitiveCount > 0) score += 55;
    if (count >= m_minFileCount) score += 35;
    score = std::min(100u, score);

    std::string samples;
    uint32_t sampleCount = 0;
    for (const auto& file : state.files) {
        if (sampleCount >= 4) break;
        if (!samples.empty()) samples += ",";
        samples += file.first;
        ++sampleCount;
    }

    event.fields[field::kUsbExfilScore] = std::to_string(score);
    event.fields[field::kUsbExfilCount] = std::to_string(count);
    event.fields[field::kUsbExfilDrive] = drive;
    event.fields[field::kUsbExfilWindowSeconds] =
        std::to_string(m_windowSeconds);
    event.fields[field::kUsbExfilSensitive] =
        sensitiveCount > 0 ? "true" : "false";
    event.fields[field::kUsbExfilSamples] = samples;
    const std::string verdict = Verdict(score);
    if (!verdict.empty()) event.fields[field::kUsbExfilVerdict] = verdict;
}

void UsbExfilDetector::Enrich(Event& event) {
    if (!m_enabled) return;
    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    if (event.type == EDR_EVT_USB_DEVICE) {
        const std::string action = LowerAscii(
            FieldValue(event, field::kUsbAction));
        const std::string drive =
            FieldValue(event, field::kUsbDriveLetter);
        if (drive.empty()) return;
        std::string letter = drive;
        if (letter.size() >= 1) {
            letter[0] = static_cast<char>(
                std::toupper(static_cast<unsigned char>(letter[0])));
        }
        if (action == "added") {
            m_removable[letter] = now;
        } else if (action == "removed") {
            m_removable.erase(letter);
            m_drives.erase(letter);
        }
        while (m_removable.size() > m_stateCapacity) {
            m_removable.erase(m_removable.begin());
        }
        return;
    }

    if (event.type != EDR_EVT_FILE_CREATE &&
        event.type != EDR_EVT_FILE_RENAME) {
        return;
    }
    const std::string path = FieldValue(event, field::kFilePath);
    if (path.empty()) return;
    const std::string drive = DriveLetterOf(path);
    if (drive.empty() || m_removable.count(drive) == 0) return;

    DriveState& state = m_drives[drive];
    state.lastSeen100ns = now;
    state.files[path] = now;
    EvictOldest(m_drives, m_stateCapacity);

    uint32_t count = 0;
    uint32_t sensitiveCount = 0;
    for (const auto& file : state.files) {
        if (now >= file.second && now - file.second <= m_window100ns) {
            ++count;
            if (IsSensitiveExtension(file.first)) ++sensitiveCount;
        }
    }
    if (sensitiveCount == 0 && count < m_minFileCount) return;
    if (state.lastStamp100ns != 0 && now >= state.lastStamp100ns &&
        now - state.lastStamp100ns <= m_dedup100ns) {
        return;
    }
    state.lastStamp100ns = now;

    WriteState(event, state, drive, count, sensitiveCount);
}

} // namespace edr
