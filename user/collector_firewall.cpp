/*
 * collector_firewall.cpp - Windows Firewall rule monitoring collector.
 *
 * Every poll reads one bounded, complete registry snapshot. Failed or partial
 * reads retain the prior baseline; an explicitly missing key is a complete
 * empty snapshot and remains observable through collector health.
 */
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <limits>
#include <map>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "collector.h"
#include "collector_firewall.h"
#include "collector_runtime_health.h"
#include "config.h"
#include "edr_event.h"

namespace edr {
namespace {

constexpr const wchar_t* kFirewallRulesKey =
    L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\"
    L"FirewallPolicy\\FirewallRules";
constexpr size_t kMaxEnumRetries = 8;

struct FirewallRule {
    std::string name;
    std::string rawValue;
    std::string dir;
    std::string action;
    std::string protocol;
    std::string localPort;
    std::string remotePort;
    std::string app;
    std::string service;
    bool enabled = true;
};

std::string Lower(std::string value) {
    for (char& ch : value)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return value;
}

bool ValidUtf8(const std::string& value) {
    return value.find('\0') == std::string::npos &&
        (value.empty() || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            value.data(), static_cast<int>(value.size()), nullptr, 0) != 0);
}

bool WideToUtf8Checked(const wchar_t* value, size_t length, std::string& output) {
    output.clear();
    if (length == 0) return true;
    if (!value || length > static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;
    const int inputLength = static_cast<int>(length);
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
        inputLength, nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return false;
    output.resize(static_cast<size_t>(bytes));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
        inputLength, output.data(), bytes, nullptr, nullptr) == bytes &&
        output.find('\0') == std::string::npos;
}

bool ConvertRegistryText(const wchar_t* value, size_t characters,
                         std::string& output) {
    if (!value) return false;
    size_t length = characters;
    while (length != 0 && value[length - 1] == L'\0') --length;
    for (size_t i = 0; i < length; ++i)
        if (value[i] == L'\0') return false;
    return WideToUtf8Checked(value, length, output);
}

bool WithinLimits(const FirewallCollectorSnapshot& snapshot,
                  const FirewallSnapshotLimits& limits) {
    if (snapshot.status == FirewallSnapshotStatus::Failed) return false;
    if (snapshot.status == FirewallSnapshotStatus::Missing)
        return snapshot.values.empty();
    if (snapshot.status != FirewallSnapshotStatus::Complete ||
        snapshot.values.size() > limits.maxValues) return false;
    size_t payload = 0;
    for (const auto& item : snapshot.values) {
        if (item.first.empty() || item.first.size() > limits.maxNameBytes ||
            item.second.size() > limits.maxValueBytes ||
            !ValidUtf8(item.first) || !ValidUtf8(item.second)) return false;
        if (item.first.size() > limits.maxTotalPayloadBytes - payload)
            return false;
        payload += item.first.size();
        if (item.second.size() > limits.maxTotalPayloadBytes - payload)
            return false;
        payload += item.second.size();
    }
    return true;
}

FirewallRule ParseRule(const std::string& name, const std::string& value) {
    FirewallRule rule;
    rule.name = name;
    rule.rawValue = value;
    size_t pos = 0;
    while (pos < value.size()) {
        const size_t pipe = value.find('|', pos);
        const std::string token = value.substr(pos,
            pipe == std::string::npos ? std::string::npos : pipe - pos);
        pos = pipe == std::string::npos ? value.size() : pipe + 1;
        const size_t eq = token.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = token.substr(0, eq);
        const std::string fieldValue = token.substr(eq + 1);
        if (key == "Dir") rule.dir = Lower(fieldValue);
        else if (key == "Action") rule.action = Lower(fieldValue);
        else if (key == "Protocol") {
            if (fieldValue == "6") rule.protocol = "tcp";
            else if (fieldValue == "17") rule.protocol = "udp";
            else if (fieldValue == "any") rule.protocol = "any";
            else rule.protocol = Lower(fieldValue);
        } else if (key == "LPort") rule.localPort = fieldValue;
        else if (key == "RPort") rule.remotePort = fieldValue;
        else if (key == "App") rule.app = fieldValue;
        else if (key == "svc") rule.service = fieldValue;
        else if (key == "Active") rule.enabled = Lower(fieldValue) == "true";
        /* Name= is intentionally not mapped: the existing event's rule_name
         * remains the registry value id, and no display-name field exists. */
    }
    return rule;
}

bool SameRuleFields(const FirewallRule& left, const FirewallRule& right) {
    return left.name == right.name && left.rawValue == right.rawValue &&
        left.dir == right.dir &&
        left.action == right.action && left.protocol == right.protocol &&
        left.localPort == right.localPort && left.remotePort == right.remotePort &&
        left.app == right.app && left.service == right.service &&
        left.enabled == right.enabled;
}

FirewallCollectorSnapshot ReadNativeSnapshot() {
    HKEY key = nullptr;
    const LONG openResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        kFirewallRulesKey, 0, KEY_READ, &key);
    if (openResult == ERROR_FILE_NOT_FOUND || openResult == ERROR_PATH_NOT_FOUND)
        return {FirewallSnapshotStatus::Missing, {}};
    if (openResult != ERROR_SUCCESS) return {};
    struct KeyCloser {
        HKEY value;
        ~KeyCloser() { if (value) RegCloseKey(value); }
    } close{key};
    return ReadFirewallRegistrySnapshot(key);
}

struct FirewallRegistryMetadata {
    DWORD valueCount = 0;
    DWORD maxNameCharacters = 0;
    DWORD maxValueBytes = 0;
    FILETIME lastWrite{};
};

bool QueryFirewallRegistryMetadata(HKEY key, FirewallRegistryMetadata& metadata) {
    return RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, &metadata.valueCount, &metadata.maxNameCharacters,
        &metadata.maxValueBytes, nullptr, &metadata.lastWrite) == ERROR_SUCCESS;
}

bool SameFirewallRegistryVersion(const FirewallRegistryMetadata& left,
                                 const FirewallRegistryMetadata& right) {
    return left.valueCount == right.valueCount &&
        left.lastWrite.dwLowDateTime == right.lastWrite.dwLowDateTime &&
        left.lastWrite.dwHighDateTime == right.lastWrite.dwHighDateTime;
}

} // namespace

FirewallCollectorSnapshot ReadFirewallRegistrySnapshot(
    HKEY key, const FirewallSnapshotLimits& limits,
    FirewallSnapshotReadHook afterValueRead) {
    if (!key) return {};
    for (size_t attempt = 0; attempt < kMaxEnumRetries; ++attempt) {
        FirewallRegistryMetadata before;
        if (!QueryFirewallRegistryMetadata(key, before) ||
            before.maxNameCharacters > 16383 ||
            before.maxNameCharacters > limits.maxNameBytes ||
            before.maxValueBytes > limits.maxValueBytes ||
            before.valueCount > limits.maxEnumeratedValues ||
            before.valueCount > limits.maxValues) return {};

        std::vector<wchar_t> name(
            static_cast<size_t>(before.maxNameCharacters) + 2, L'\0');
        std::vector<BYTE> data(
            static_cast<size_t>(before.maxValueBytes) + sizeof(wchar_t), 0);
        FirewallCollectorSnapshot candidate;
        candidate.status = FirewallSnapshotStatus::Complete;
        size_t totalPayload = 0;
        size_t enumerated = 0;
        bool candidateValid = true;
        bool observedDrift = false;

        for (DWORD index = 0;; ++index) {
            LONG result = ERROR_SUCCESS;
            DWORD nameLength = 0;
            DWORD dataLength = 0;
            DWORD type = 0;
            for (size_t resizeAttempt = 0; resizeAttempt < kMaxEnumRetries;
                 ++resizeAttempt) {
                nameLength = static_cast<DWORD>(name.size() - 1);
                dataLength = static_cast<DWORD>(data.size());
                type = 0;
                result = RegEnumValueW(key, index, name.data(), &nameLength,
                    nullptr, &type, data.data(), &dataLength);
                if (result != ERROR_MORE_DATA) break;
                bool grew = false;
                if (nameLength >= name.size() - 1) {
                    if (nameLength > 16383 || nameLength > limits.maxNameBytes) {
                        candidateValid = false;
                        break;
                    }
                    name.resize(static_cast<size_t>(nameLength) + 2, L'\0');
                    grew = true;
                }
                if (dataLength > data.size()) {
                    if (dataLength > limits.maxValueBytes) {
                        candidateValid = false;
                        break;
                    }
                    data.resize(static_cast<size_t>(dataLength) + sizeof(wchar_t), 0);
                    grew = true;
                }
                if (!grew) {
                    observedDrift = true;
                    break;
                }
            }
            if (!candidateValid || observedDrift) break;

            if (index == before.valueCount) {
                if (result != ERROR_NO_MORE_ITEMS) observedDrift = true;
                break;
            }
            if (result == ERROR_NO_MORE_ITEMS) {
                observedDrift = true;
                break;
            }
            if (result != ERROR_SUCCESS) {
                candidateValid = false;
                break;
            }
            if (nameLength > 16383 || nameLength > limits.maxNameBytes ||
                (type != REG_SZ && type != REG_EXPAND_SZ) ||
                dataLength % sizeof(wchar_t) != 0 ||
                dataLength > limits.maxValueBytes ||
                ++enumerated > limits.maxEnumeratedValues) {
                candidateValid = false;
                break;
            }
            name[nameLength] = L'\0';
            const size_t valueCharacters = dataLength / sizeof(wchar_t);
            const auto* wideData = reinterpret_cast<const wchar_t*>(data.data());
            std::string utf8Name;
            std::string utf8Value;
            if (!ConvertRegistryText(name.data(), nameLength, utf8Name) ||
                utf8Name.empty() || !ConvertRegistryText(wideData,
                    valueCharacters, utf8Value) ||
                utf8Name.size() > limits.maxNameBytes ||
                utf8Value.size() > limits.maxValueBytes ||
                utf8Name.size() > limits.maxTotalPayloadBytes - totalPayload) {
                candidateValid = false;
                break;
            }
            totalPayload += utf8Name.size();
            if (utf8Value.size() > limits.maxTotalPayloadBytes - totalPayload) {
                candidateValid = false;
                break;
            }
            totalPayload += utf8Value.size();
            if (!candidate.values.emplace(std::move(utf8Name),
                                          std::move(utf8Value)).second) {
                candidateValid = false;
                break;
            }
            if (afterValueRead) afterValueRead(attempt, enumerated);
        }

        FirewallRegistryMetadata after;
        if (!QueryFirewallRegistryMetadata(key, after)) return {};
        if (observedDrift || !SameFirewallRegistryVersion(before, after))
            continue;
        if (!candidateValid || enumerated != before.valueCount ||
            candidate.values.size() != before.valueCount) return {};
        return candidate;
    }
    return {};
}

class FirewallCollector : public ICollector {
public:
    explicit FirewallCollector(uint32_t pollMs, FirewallCollectorQuery query = {})
        : m_pollMs(std::max(1u, pollMs)), m_query(std::move(query)) {}
    ~FirewallCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) return !m_workerFailed.load();
        if (!bus) return false;
        m_bus = bus;
        m_stop.store(false);
        m_explicitStop.store(false);
        m_workerFailed.store(false);
        try {
            m_thread = std::thread(&FirewallCollector::Run, this);
        } catch (...) {
            m_stop.store(true);
            m_workerFailed.store(true);
            m_health.RecordSourceError();
            m_bus = nullptr;
            return false;
        }
        return true;
    }

    void Stop() override {
        m_explicitStop.store(true);
        m_stop.store(true);
        if (m_thread.joinable()) m_thread.join();
        m_bus = nullptr;
    }

    CollectorHealthSnapshot GetHealthSnapshot() const override {
        auto sample = m_health.Snapshot(
            !m_explicitStop.load() && m_workerFailed.load() ? "source_error" : "stopped");
        const bool missing = m_keyMissing.load();
        if (sample.running && missing) sample.state = "source_missing";
        sample.counters["key_missing"] = missing ? 1 : 0;
        sample.counters["missing_snapshots"] = m_missingSnapshots.load();
        sample.counters["retained_rules"] = m_retainedRules.load();
        return sample;
    }

private:
    void Emit(const FirewallRule& rule, const char* action) {
        Event event;
        event.type = EDR_EVT_FIREWALL_RULE;
        event.source = "firewall_monitor";
        FILETIME now = {};
        GetSystemTimePreciseAsFileTime(&now);
        event.ts100ns = (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
                        now.dwLowDateTime;
        event.fields[field::kSource] = event.source;
        event.fields[field::kType] = "FIREWALL_RULE";
        event.fields[field::kFirewallAction] = action;
        event.fields[field::kFirewallRuleName] = rule.name;
        if (!rule.dir.empty()) event.fields[field::kFirewallDir] = rule.dir;
        if (!rule.action.empty()) event.fields[field::kFirewallRuleAction] = rule.action;
        if (!rule.protocol.empty()) event.fields[field::kFirewallProtocol] = rule.protocol;
        if (!rule.localPort.empty()) event.fields[field::kFirewallLocalPort] = rule.localPort;
        if (!rule.remotePort.empty()) event.fields[field::kFirewallRemotePort] = rule.remotePort;
        if (!rule.app.empty()) event.fields[field::kFirewallApp] = rule.app;
        if (!rule.service.empty()) event.fields[field::kFirewallService] = rule.service;
        event.fields[field::kFirewallEnabled] = rule.enabled ? "true" : "false";
        if (m_bus) m_health.RecordEventSubmitted(!m_bus->Push(event));
    }

    bool ReadSnapshot(FirewallCollectorSnapshot& result) {
        result = m_query ? m_query() : ReadNativeSnapshot();
        if (!WithinLimits(result, m_limits)) {
            m_health.RecordSourceError();
            m_keyMissing.store(false);
            return false;
        }
        const bool missing = result.status == FirewallSnapshotStatus::Missing;
        m_keyMissing.store(missing);
        if (missing) m_missingSnapshots.fetch_add(1);
        m_health.RecordSnapshotSuccess();
        return true;
    }

    void Run() noexcept {
        m_health.WorkerStarted();
        try {
            std::map<std::string, FirewallRule> previous;
            bool seeded = false;
            while (!m_stop.load()) {
                FirewallCollectorSnapshot snapshot;
                if (ReadSnapshot(snapshot)) {
                    std::map<std::string, FirewallRule> current;
                    if (snapshot.status == FirewallSnapshotStatus::Complete) {
                        for (const auto& value : snapshot.values)
                            current.emplace(value.first, ParseRule(value.first, value.second));
                    }
                    if (seeded) {
                        for (const auto& item : current) {
                            const auto old = previous.find(item.first);
                            if (old == previous.end()) Emit(item.second, "added");
                            else if (!SameRuleFields(old->second, item.second))
                                Emit(item.second, "modified");
                        }
                        for (const auto& item : previous)
                            if (current.find(item.first) == current.end())
                                Emit(item.second, "removed");
                    }
                    previous = std::move(current);
                    seeded = true;
                    m_retainedRules.store(previous.size());
                }
                uint32_t remaining = m_pollMs;
                while (remaining != 0 && !m_stop.load()) {
                    const uint32_t delay = std::min(remaining, 100u);
                    Sleep(delay);
                    remaining -= delay;
                }
            }
        } catch (...) {
            m_keyMissing.store(false);
            m_workerFailed.store(true);
            m_health.RecordSourceError();
        }
        m_health.WorkerStopped();
    }

    uint32_t m_pollMs;
    FirewallCollectorQuery m_query;
    FirewallSnapshotLimits m_limits;
    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_explicitStop{false};
    std::atomic<bool> m_workerFailed{false};
    std::atomic<bool> m_keyMissing{false};
    std::atomic<uint64_t> m_missingSnapshots{0};
    std::atomic<uint64_t> m_retainedRules{0};
    CollectorRuntimeHealth m_health;
};

ICollector* CreateFirewallCollector(uint32_t pollMs) {
    return new FirewallCollector(pollMs);
}

ICollector* CreateFirewallCollector(uint32_t pollMs, FirewallCollectorQuery query) {
    return new FirewallCollector(pollMs, std::move(query));
}

} // namespace edr
