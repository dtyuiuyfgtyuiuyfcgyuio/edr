/*
 * ransom_burst_detector.cpp - See ransom_burst_detector.h.
 *
 * Per attribution key, FILE_CREATE events are counted within a rolling
 * window. When at least minFileCount creations show at least
 * minDistinctExtensions distinct extensions, the current event is stamped
 * with bulk_file_score (min(100, count)), bulk_file_count,
 * bulk_file_extensions (first 24 extensions, comma-separated), and
 * bulk_file_window_seconds. Each key is flagged once per window; when the key
 * expires it is dropped so the flag resets and the threshold must be re-met
 * before fields are emitted again. A basename with no '.' contributes its
 * full basename as the extension so extensionless files count as distinct.
 */
#include "ransom_burst_detector.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
constexpr size_t kMaxExtensionsField = 24;

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

/* Directory of value, lowercased, up to and including the last '\' or '/'.
 * A value with no separator yields the empty string. */
std::string DirectoryName(const std::string& value) {
    std::string lower = LowerAscii(value);
    size_t slash = lower.find_last_of("\\/");
    return slash == std::string::npos ? std::string()
                                      : lower.substr(0, slash + 1);
}

/* Lowercased extension of a file path: everything after the last '.' in the
 * basename. A basename with no '.' contributes its full basename so every
 * extensionless file counts as a distinct extension. */
std::string ExtensionOf(const std::string& filePath) {
    std::string lower = BaseName(filePath);
    size_t dot = lower.find_last_of('.');
    return dot == std::string::npos ? lower : lower.substr(dot + 1);
}

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
}

std::string Join(const std::vector<std::string>& values,
                 const char* separator) {
    std::string result;
    for (const std::string& value : values) {
        if (!result.empty()) result += separator;
        result += value;
    }
    return result;
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

RansomBurstDetector::RansomBurstDetector(bool enabled, uint32_t windowSeconds,
                                         size_t stateCapacity,
                                         uint32_t minFileCount,
                                         uint32_t minDistinctExtensions)
    : m_enabled(enabled),
      m_window100ns(static_cast<uint64_t>(windowSeconds) *
                    kFiletimeTicksPerSecond),
      m_windowSeconds(windowSeconds),
      m_stateCapacity(std::max<size_t>(1, stateCapacity)),
      m_minFileCount(minFileCount),
      m_minDistinctExtensions(minDistinctExtensions) {}

bool RansomBurstDetector::Inspects(uint16_t type) {
    return type == EDR_EVT_FILE_CREATE;
}

void RansomBurstDetector::PurgeExpired(uint64_t now100ns) {
    for (auto it = m_keys.begin(); it != m_keys.end();) {
        if (now100ns >= it->second.lastSeen100ns &&
            now100ns - it->second.lastSeen100ns > m_window100ns)
            it = m_keys.erase(it);
        else
            ++it;
    }
}

void RansomBurstDetector::WriteState(Event& event, const KeyState& state) {
    std::vector<std::string> extensions;
    for (const std::string& extension : state.extensions) {
        if (extensions.size() >= kMaxExtensionsField) break;
        extensions.push_back(extension);
    }
    event.fields[field::kRansomBurstScore] =
        std::to_string(std::min(100u, state.count));
    event.fields[field::kRansomBurstCount] = std::to_string(state.count);
    event.fields[field::kRansomBurstExtensions] = Join(extensions, ",");
    event.fields[field::kRansomBurstWindowSeconds] =
        std::to_string(m_windowSeconds);
}

void RansomBurstDetector::Enrich(Event& event) {
    if (!m_enabled) return;

    const uint64_t now = EventTime(event);
    PurgeExpired(now);

    const std::string image = FieldValue(event, field::kImage);
    const std::string filePath = FieldValue(event, field::kFilePath);

    std::string key;
    if (event.pid > 0 && !image.empty()) {
        key = "pid:" + std::to_string(event.pid) + "@" + BaseName(image);
    } else if (!filePath.empty()) {
        key = "dir:" + DirectoryName(filePath);
    } else {
        return; /* No attribution possible. */
    }

    KeyState& state = m_keys[key];
    ++state.count;
    state.extensions.insert(ExtensionOf(filePath));
    state.lastSeen100ns = now;

    if (!state.flagged && state.count >= m_minFileCount &&
        state.extensions.size() >= m_minDistinctExtensions) {
        state.flagged = true;
        WriteState(event, state);
    }

    EvictOldest(m_keys, m_stateCapacity);
}

} // namespace edr