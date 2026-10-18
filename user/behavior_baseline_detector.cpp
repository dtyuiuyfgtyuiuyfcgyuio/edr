/*
 * behavior_baseline_detector.cpp - See behavior_baseline_detector.h.
 *
 * Observation keys are lowercased image basenames: PROCESS_START keys on the
 * parent image (learning which children it spawns), FILE_CREATE and
 * NET_CONNECT key on the acting image (learning which directories it writes
 * and which endpoints it contacts). Events without the attribution fields
 * are skipped rather than learned under a shared or empty key.
 */
#include "behavior_baseline_detector.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <limits>
#include <vector>

#include "json_lite.h"

namespace edr {
namespace {

constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
constexpr uint64_t kUnixEpoch100ns = 116444736000000000ULL;
/* Keep persisted UTC seconds inside the exact integer range of JSON doubles
 * and a useful FILETIME/calendar range. */
constexpr uint64_t kMaxUnixSeconds = 253402300799ULL;
constexpr uint64_t kMaxFutureSkewSeconds = 300ULL;
constexpr size_t   kMaxFileBytes = 8u * 1024u * 1024u;
constexpr size_t   kMaxKeyLength = 256;
constexpr uint32_t kChildDeviationPoints = 40;
constexpr uint32_t kDirDeviationPoints = 30;
constexpr uint32_t kEndpointDeviationPoints = 30;
std::atomic<uint64_t> g_tempSequence{0};

uint64_t EventTime(const Event& event) {
    if (event.ts100ns != 0) return event.ts100ns;
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
            now.dwLowDateTime;
}

uint64_t Now100ns() {
    FILETIME now = {};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
            now.dwLowDateTime;
}

uint64_t NowUnix() {
    return (Now100ns() - kUnixEpoch100ns) / kFiletimeTicksPerSecond;
}

std::string BaseName(const std::string& value) {
    const size_t slash = value.find_last_of("\\/");
    std::string base = slash == std::string::npos ? value
                                                  : value.substr(slash + 1);
    for (char& c : base) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    }
    return base;
}

std::string DirectoryOf(const std::string& value) {
    const size_t slash = value.find_last_of("\\/");
    if (slash == std::string::npos || slash == 0) return {};
    std::string dir = value.substr(0, slash);
    for (char& c : dir) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    }
    return dir;
}

std::string FieldValue(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

bool ParseNumber(const std::string& text, uint64_t& out) {
    if (text.empty()) return false;
    try {
        size_t parsed = 0;
        const long long value = std::stoll(text, &parsed);
        if (parsed != text.size() || value < 0) return false;
        out = static_cast<uint64_t>(value);
        return true;
    } catch (...) {
        return false;
    }
}

bool ParseUnixSeconds(const jsonlite::Value* value, uint64_t& out) {
    if (!value || value->type != jsonlite::Type::Number ||
        !std::isfinite(value->number) || value->number < 0.0 ||
        std::floor(value->number) != value->number ||
        value->number > static_cast<double>(kMaxUnixSeconds))
        return false;
    out = static_cast<uint64_t>(value->number);
    return true;
}

bool ParseUint64Decimal(const std::string& text, uint64_t& out) {
    if (text.empty()) return false;
    uint64_t value = 0;
    for (unsigned char ch : text) {
        if (ch < '0' || ch > '9') return false;
        const uint64_t digit = ch - '0';
        if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10)
            return false;
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

bool CreateUniqueTemp(const std::string& target, std::string& tempPath,
                      HANDLE& file) {
    for (unsigned attempt = 0; attempt < 64; ++attempt) {
        const uint64_t sequence = g_tempSequence.fetch_add(
            1, std::memory_order_relaxed);
        tempPath = target + ".tmp." + std::to_string(GetCurrentProcessId()) +
                   "." + std::to_string(Now100ns()) + "." +
                   std::to_string(sequence);
        file = CreateFileA(tempPath.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file != INVALID_HANDLE_VALUE) return true;
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS)
            return false;
    }
    SetLastError(ERROR_FILE_EXISTS);
    return false;
}

template <typename Map>
void EvictOldest(Map& map, size_t capacity) {
    if (map.size() <= capacity) return;
    auto oldest = std::min_element(map.begin(), map.end(),
        [](const auto& a, const auto& b) {
            return a.second.lastSeen100ns < b.second.lastSeen100ns;
        });
    if (oldest != map.end()) map.erase(oldest);
}

std::string SerializeList(const std::set<std::string>& values) {
    std::string out;
    bool first = true;
    for (const std::string& value : values) {
        if (!first) out += ",";
        first = false;
        out += "\"";
        out += jsonlite::escape(value);
        out += "\"";
    }
    return out;
}

} // namespace

BehaviorBaselineDetector::BehaviorBaselineDetector(const Options& options)
    : m_options(options) {
    if (m_options.trainingSeconds > 31536000u)
        m_options.trainingSeconds = 31536000u;
    if (m_options.windowSeconds == 0) m_options.windowSeconds = 1;
    if (m_options.stateCapacity == 0) m_options.stateCapacity = 1;
    if (m_options.maxObservations == 0) m_options.maxObservations = 1;
    if (m_options.maxAgeDays > 3650) m_options.maxAgeDays = 3650;
    if (m_options.enabled) (void)Load();
}

bool BehaviorBaselineDetector::Polluted(const Event& event) const {
    const std::string chain = FieldValue(event, "chain_score");
    if (chain.empty()) return false;
    uint64_t score = 0;
    if (!ParseNumber(chain, score)) return false;
    return score >= m_options.pollutionScore;
}

void BehaviorBaselineDetector::EvaluateDeviation(Entry& entry, Event& event,
                                                 uint64_t now,
                                                 const std::string& key,
                                                 bool freshChild,
                                                 bool freshDir,
                                                 bool freshEndpoint) {
    if (!entry.trained) return;
    if (!freshChild && !freshDir && !freshEndpoint) return;

    const uint64_t window100ns =
        static_cast<uint64_t>(m_options.windowSeconds) *
        kFiletimeTicksPerSecond;
    auto active = [now, window100ns](uint64_t mark) {
        return mark != 0 && now >= mark && now - mark <= window100ns;
    };
    const bool childActive = active(entry.childDeviation100ns);
    const bool dirActive = active(entry.dirDeviation100ns);
    const bool endpointActive = active(entry.endpointDeviation100ns);
    if (!childActive && !dirActive && !endpointActive) return;

    uint32_t score = 0;
    std::string signals;
    auto Mark = [&score, &signals](bool on, uint32_t points, const char* name) {
        if (!on) return;
        score += points;
        if (!signals.empty()) signals += ",";
        signals += name;
    };
    Mark(childActive, kChildDeviationPoints, "new_child");
    Mark(dirActive, kDirDeviationPoints, "new_dir");
    Mark(endpointActive, kEndpointDeviationPoints, "new_endpoint");
    if (score < m_options.minScore) return;

    const uint64_t dedup100ns =
        static_cast<uint64_t>(m_options.dedupSeconds) *
        kFiletimeTicksPerSecond;
    if (entry.lastDeviation100ns != 0 && now >= entry.lastDeviation100ns &&
        now - entry.lastDeviation100ns <= dedup100ns &&
        score <= entry.lastDeviationScore)
        return;

    entry.lastDeviation100ns = now;
    entry.lastDeviationScore = std::min(100u, score);
    event.fields[field::kBehaviorBaselineScore] =
        std::to_string(std::min(100u, score));
    event.fields[field::kBehaviorBaselineSignals] = signals;
    event.fields[field::kBehaviorBaselineImage] = key;
    event.fields[field::kBehaviorBaselineState] = "active";
    if (freshChild)
        event.fields[field::kBehaviorBaselineNewChild] =
            BaseName(FieldValue(event, field::kImage));
    if (freshDir) {
        const std::string path = FieldValue(event, field::kTargetPath).empty()
                                     ? FieldValue(event, field::kFilePath)
                                     : FieldValue(event, field::kTargetPath);
        event.fields[field::kBehaviorBaselineNewDir] = DirectoryOf(path);
    }
    if (freshEndpoint) {
        const std::string ip = FieldValue(event, field::kDstIp);
        const std::string port = FieldValue(event, field::kDstPort);
        event.fields[field::kBehaviorBaselineNewEndpoint] =
            port.empty() ? ip : ip + ":" + port;
    }
}

void BehaviorBaselineDetector::LearnProcessStart(Entry& entry, Event& event,
                                                 uint64_t now, bool trained,
                                                 const std::string& key) {
    const std::string image = BaseName(FieldValue(event, field::kImage));
    if (image.empty()) return;
    if (entry.children.find(image) != entry.children.end()) return;

    if (!trained) {
        if (!entry.polluted &&
            entry.children.size() < m_options.maxObservations)
            entry.children.insert(image);
        return;
    }

    /* Trained and frozen: the unseen child is a deviation. Learning stays
     * frozen even when the key is polluted; pollution only blocks learning. */
    entry.childDeviation100ns = now;
    EvaluateDeviation(entry, event, now, key, true, false, false);
}

void BehaviorBaselineDetector::LearnFileCreate(Entry& entry, Event& event,
                                               uint64_t now, bool trained,
                                               const std::string& key) {
    const std::string path = FieldValue(event, field::kTargetPath).empty()
                                 ? FieldValue(event, field::kFilePath)
                                 : FieldValue(event, field::kTargetPath);
    const std::string dir = DirectoryOf(path);
    if (dir.empty()) return;
    if (entry.dirs.find(dir) != entry.dirs.end()) return;

    if (!trained) {
        if (!entry.polluted && entry.dirs.size() < m_options.maxObservations)
            entry.dirs.insert(dir);
        return;
    }
    entry.dirDeviation100ns = now;
    EvaluateDeviation(entry, event, now, key, false, true, false);
}

void BehaviorBaselineDetector::LearnNetConnect(Entry& entry, Event& event,
                                               uint64_t now, bool trained,
                                               const std::string& key) {
    const std::string ip = FieldValue(event, field::kDstIp);
    if (ip.empty()) return;
    const std::string port = FieldValue(event, field::kDstPort);
    const std::string endpoint = port.empty() ? ip : ip + ":" + port;
    if (entry.endpoints.find(endpoint) != entry.endpoints.end()) return;

    if (!trained) {
        if (!entry.polluted &&
            entry.endpoints.size() < m_options.maxObservations)
            entry.endpoints.insert(endpoint);
        return;
    }
    entry.endpointDeviation100ns = now;
    EvaluateDeviation(entry, event, now, key, false, false, true);
}

void BehaviorBaselineDetector::Enrich(Event& event) {
    if (!m_options.enabled || !Inspects(event.type)) return;
    const uint64_t now = EventTime(event);
    if (now > Now100ns() + kMaxFutureSkewSeconds * kFiletimeTicksPerSecond)
        return; /* A future source clock must not poison live or saved state. */

    std::string key;
    std::string observed;
    if (event.type == EDR_EVT_PROCESS_START) {
        const std::string parent = FieldValue(event, field::kParentImage);
        const std::string image = FieldValue(event, field::kImage);
        if (ContainsNul(parent) || ContainsNul(image) || image.size() > 512)
            return;
        key = BaseName(parent);
        observed = BaseName(image);
    } else {
        const std::string image = FieldValue(event, field::kImage);
        if (ContainsNul(image) || image.size() > 512) return;
        key = BaseName(image);
        if (event.type == EDR_EVT_FILE_CREATE) {
            const std::string path = FieldValue(event, field::kTargetPath).empty()
                                         ? FieldValue(event, field::kFilePath)
                                         : FieldValue(event, field::kTargetPath);
            if (path.size() > 512 || ContainsNul(path)) return;
            observed = DirectoryOf(path);
        } else {
            const std::string ip = FieldValue(event, field::kDstIp);
            const std::string port = FieldValue(event, field::kDstPort);
            if (ip.size() > 512 || port.size() > 512 || ContainsNul(ip) ||
                ContainsNul(port))
                return;
            observed = port.empty() ? ip : ip + ":" + port;
        }
    }
    if (key.empty() || key.size() > kMaxKeyLength || ContainsNul(key) ||
        !BoundedValue(observed))
        return; /* No safe, bounded attribution/observation is available. */

    auto found = m_entries.find(key);
    if (found != m_entries.end() && now < found->second.lastSeen100ns)
        return; /* Late events cannot rewind training, marks, or eviction. */

    Entry& entry = m_entries[key];
    bool firstSighting = entry.firstSeen100ns == 0;
    if (!firstSighting) {
        const uint64_t maxAge100ns =
            static_cast<uint64_t>(m_options.maxAgeDays) * 86400ULL *
            kFiletimeTicksPerSecond;
        if (now >= entry.firstSeen100ns &&
            now - entry.firstSeen100ns > maxAge100ns) {
            entry = Entry{};
            firstSighting = true;
        }
    }
    if (firstSighting) entry.firstSeen100ns = now;
    entry.lastSeen100ns = now;

    const uint64_t training100ns =
        static_cast<uint64_t>(m_options.trainingSeconds) *
        kFiletimeTicksPerSecond;
    const bool trained = entry.trained ||
        (now >= entry.firstSeen100ns &&
         now - entry.firstSeen100ns >= training100ns);
    if (trained) entry.trained = true;

    /* The first sighting of a key always seeds its category: an empty
     * baseline must not report the entry that created it. */
    const bool learnable = trained && !firstSighting;

    if (event.type == EDR_EVT_PROCESS_START && Polluted(event))
        entry.polluted = true;

    switch (event.type) {
    case EDR_EVT_PROCESS_START:
        LearnProcessStart(entry, event, now, learnable, key);
        break;
    case EDR_EVT_FILE_CREATE:
        LearnFileCreate(entry, event, now, learnable, key);
        break;
    case EDR_EVT_NET_CONNECT:
        LearnNetConnect(entry, event, now, learnable, key);
        break;
    default:
        break;
    }

    EvictOldest(m_entries, m_options.stateCapacity);
}

bool BehaviorBaselineDetector::Save() {
    if (!m_options.enabled) {
        m_lastError = "behavior baseline is disabled";
        return false;
    }
    if (m_options.baselinePath.empty()) {
        m_lastError = "baseline path is empty";
        return false;
    }
    const std::string body = Serialize();
    if (body.size() > kMaxFileBytes) {
        m_lastError = "baseline exceeds the file size cap";
        return false;
    }
    std::string tmp;
    HANDLE file = INVALID_HANDLE_VALUE;
    if (!CreateUniqueTemp(m_options.baselinePath, tmp, file)) {
        m_lastError = "baseline temp create failed";
        return false;
    }
    size_t written = 0;
    bool ok = true;
    while (written < body.size()) {
        DWORD chunk = 0;
        const DWORD want = static_cast<DWORD>(
            std::min<size_t>(body.size() - written, 65536));
        if (!WriteFile(file, body.data() + written, want, &chunk, nullptr) ||
            chunk != want) {
            ok = false;
            break;
        }
        written += chunk;
    }
    if (ok) ok = FlushFileBuffers(file) != FALSE;
    CloseHandle(file);
    if (!ok) {
        DeleteFileA(tmp.c_str());
        m_lastError = "baseline temp write failed";
        return false;
    }
    if (!MoveFileExA(tmp.c_str(), m_options.baselinePath.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileA(tmp.c_str());
        m_lastError = "baseline replace failed";
        return false;
    }
    m_lastError.clear();
    return true;
}

std::string BehaviorBaselineDetector::Serialize() const {
    std::string out = "{\"version\":1,\"saved_at_unix\":";
    out += std::to_string(NowUnix());
    out += ",\"entries\":{";
    bool first = true;
    for (const auto& item : m_entries) {
        const Entry& entry = item.second;
        if (!first) out += ",";
        first = false;
        out += "\"";
        out += jsonlite::escape(item.first);
        out += "\":{\"children\":[";
        out += SerializeList(entry.children);
        out += "],\"dirs\":[";
        out += SerializeList(entry.dirs);
        out += "],\"endpoints\":[";
        out += SerializeList(entry.endpoints);
        out += "],\"first_seen_unix\":";
        out += std::to_string(entry.firstSeen100ns == 0
                                  ? 0
                                  : (entry.firstSeen100ns - kUnixEpoch100ns) /
                                        kFiletimeTicksPerSecond);
        out += ",\"trained\":";
        out += entry.trained ? "true" : "false";
        out += ",\"polluted\":";
        out += entry.polluted ? "true" : "false";
        out += ",\"last_seen_100ns\":\"";
        out += std::to_string(entry.lastSeen100ns);
        out += "\"";
        out += "}";
    }
    out += "}}";
    return out;
}

bool BehaviorBaselineDetector::Load() {
    m_entries.clear();
    m_loadedEntries = 0;
    m_lastError.clear();
    if (!m_options.enabled) return false;
    if (m_options.baselinePath.empty()) {
        m_lastError = "baseline path is empty";
        return false;
    }

    HANDLE file = CreateFileA(m_options.baselinePath.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        m_lastError = "baseline file not readable";
        return false;
    }
    std::string body;
    char buffer[65536];
    bool ok = true;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(file, buffer, sizeof(buffer), &got, nullptr)) {
            ok = false;
            break;
        }
        if (got == 0) break;
        body.append(buffer, got);
        if (body.size() > kMaxFileBytes) {
            ok = false;
            break;
        }
    }
    CloseHandle(file);
    if (!ok || body.empty()) {
        m_lastError = "baseline file read failed";
        return false;
    }

    jsonlite::Value root;
    try {
        root = jsonlite::parse(body);
    } catch (const std::exception&) {
        m_lastError = "baseline file is not valid JSON";
        return false;
    }
    if (root.type != jsonlite::Type::Object) {
        m_lastError = "baseline root is not an object";
        return false;
    }
    uint64_t version = 0;
    if (!ParseUnixSeconds(root.find("version"), version) || version != 1) {
        m_lastError = "baseline file version is not supported";
        return false;
    }
    uint64_t savedAtUnix = 0;
    if (!ParseUnixSeconds(root.find("saved_at_unix"), savedAtUnix)) {
        m_lastError = "baseline saved_at_unix is invalid";
        return false;
    }
    const jsonlite::Value* entries = root.find("entries");
    if (!entries || entries->type != jsonlite::Type::Object) {
        m_lastError = "baseline file has no entries object";
        return false;
    }

    const uint64_t nowUnix = NowUnix();
    if (savedAtUnix > nowUnix + kMaxFutureSkewSeconds) {
        m_lastError = "baseline saved_at_unix is too far in the future";
        return false;
    }
    const uint64_t maxAgeSeconds =
        static_cast<uint64_t>(m_options.maxAgeDays) * 86400ULL;
    const uint64_t now100ns = Now100ns();
    const uint64_t futureSkew100ns =
        kMaxFutureSkewSeconds * kFiletimeTicksPerSecond;
    const uint64_t futureCeiling100ns =
        now100ns > std::numeric_limits<uint64_t>::max() - futureSkew100ns
            ? std::numeric_limits<uint64_t>::max()
            : now100ns + futureSkew100ns;
    const uint64_t savedAt100ns =
        savedAtUnix * kFiletimeTicksPerSecond + kUnixEpoch100ns;
    if (savedAt100ns > futureCeiling100ns) {
        m_lastError = "baseline saved_at_unix is too far in the future";
        return false;
    }
    const bool fileExpired = savedAtUnix != 0 && nowUnix > savedAtUnix &&
                             nowUnix - savedAtUnix > maxAgeSeconds;
    std::unordered_map<std::string, Entry> candidate;
    for (const auto& item : entries->object) {
        const std::string& key = item.first;
        if (key.empty() || key.size() > kMaxKeyLength || ContainsNul(key) ||
            candidate.size() >= m_options.stateCapacity) {
            m_lastError = "baseline entry key or count is invalid";
            return false;
        }
        const jsonlite::Value& value = item.second;
        if (value.type != jsonlite::Type::Object) {
            m_lastError = "baseline entry is not an object";
            return false;
        }

        Entry entry;
        auto ReadList = [&](const char* name, std::set<std::string>& out) {
            const jsonlite::Value* list = value.find(name);
            if (!list || list->type != jsonlite::Type::Array ||
                list->array.size() > m_options.maxObservations)
                return false;
            for (const auto& element : list->array) {
                if (element.type != jsonlite::Type::String ||
                    !BoundedValue(element.str))
                    return false;
                out.insert(element.str);
            }
            return true;
        };
        if (!ReadList("children", entry.children) ||
            !ReadList("dirs", entry.dirs) ||
            !ReadList("endpoints", entry.endpoints)) {
            m_lastError = "baseline entry observations are invalid";
            return false;
        }

        uint64_t firstSeenUnix = 0;
        if (!ParseUnixSeconds(value.find("first_seen_unix"), firstSeenUnix) ||
            firstSeenUnix == 0 ||
            firstSeenUnix > nowUnix + kMaxFutureSkewSeconds) {
            m_lastError = "baseline entry timestamp is invalid";
            return false;
        }
        const jsonlite::Value* trained = value.find("trained");
        if (!trained || trained->type != jsonlite::Type::Bool) {
            m_lastError = "baseline entry trained flag is invalid";
            return false;
        }
        const jsonlite::Value* polluted = value.find("polluted");
        if (polluted && polluted->type != jsonlite::Type::Bool) {
            m_lastError = "baseline entry polluted flag is invalid";
            return false;
        }

        entry.firstSeen100ns = firstSeenUnix * kFiletimeTicksPerSecond +
                               kUnixEpoch100ns;
        if (entry.firstSeen100ns > futureCeiling100ns) {
            m_lastError = "baseline entry timestamp is too far in the future";
            return false;
        }
        const jsonlite::Value* lastSeen = value.find("last_seen_100ns");
        if (lastSeen) {
            if (lastSeen->type != jsonlite::Type::String ||
                !ParseUint64Decimal(lastSeen->str, entry.lastSeen100ns) ||
                entry.lastSeen100ns < entry.firstSeen100ns ||
                entry.lastSeen100ns > futureCeiling100ns) {
                m_lastError = "baseline entry last_seen_100ns is invalid";
                return false;
            }
        } else {
            /* Use the end of a legacy saved_at second to reject replay within
             * it; migration may skip less than one second of new events. */
            entry.lastSeen100ns =
                std::max(entry.firstSeen100ns,
                         savedAt100ns + kFiletimeTicksPerSecond - 1);
            if (entry.lastSeen100ns > futureCeiling100ns) {
                m_lastError = "legacy baseline cursor is too far in the future";
                return false;
            }
        }
        entry.trained = trained->boolean;
        entry.polluted = polluted && polluted->boolean;

        /* Validate every entry above, then discard globally or individually
         * expired history without publishing its learned observations. */
        const bool entryExpired = nowUnix > firstSeenUnix &&
                                  nowUnix - firstSeenUnix > maxAgeSeconds;
        if (!fileExpired && !entryExpired)
            candidate.emplace(key, std::move(entry));
    }

    if (!fileExpired) m_entries.swap(candidate);
    m_loadedEntries = m_entries.size();
    m_lastError.clear();
    return true;
}

} // namespace edr
