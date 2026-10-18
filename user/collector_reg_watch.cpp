#include <windows.h>
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <vector>
#include "collector.h"
#include "collector_reg_watch.h"
#include "collector_runtime_health.h"
#include "config.h"
#include "edr_event.h"

namespace edr {

namespace {
constexpr DWORD kMaxRegistryTelemetryBytes = 32 * 1024;
/* ExtensionSettings is one JSON value covering every managed extension. Keep
 * the normal registry telemetry budget for all other values, but allow this
 * specific browser-policy value to remain parseable at a bounded size. */
constexpr DWORD kMaxBrowserExtensionSettingsBytes = 256 * 1024;
constexpr DWORD kMaxRegistryNameCharacters = 16383;
constexpr size_t kMaxSnapshotEntryIdBytes = 64 * 1024;

bool HasBrowserPolicyRoot(const std::string& prefix) {
    static const char* const kBrowserPolicyRoots[] = {
        "\\SOFTWARE\\Policies\\Google\\Chrome",
        "\\SOFTWARE\\Policies\\Microsoft\\Edge",
    };
    for (const char* root : kBrowserPolicyRoots) {
        const size_t rootLen = std::strlen(root);
        for (size_t offset = 0; offset + rootLen <= prefix.size(); ++offset) {
            if (_strnicmp(prefix.c_str() + offset, root, rootLen) != 0)
                continue;
            const size_t suffix = offset + rootLen;
            if (suffix == prefix.size() || prefix[suffix] == '\\') return true;
        }
    }
    return false;
}

DWORD RegistryTelemetryBudget(const std::string& prefix, const wchar_t* name) {
    if (_wcsicmp(name, L"ExtensionSettings") == 0 &&
        HasBrowserPolicyRoot(prefix)) {
        return kMaxBrowserExtensionSettingsBytes;
    }
    return kMaxRegistryTelemetryBytes;
}

bool ValueAccepted(const std::vector<std::wstring>& filter,
                   const wchar_t* name) {
    if (filter.empty()) return true;
    for (const auto& accepted : filter)
        if (_wcsicmp(name, accepted.c_str()) == 0) return true;
    return false;
}
} // namespace

namespace {
size_t SnapshotPayloadBytes(const RegistrySnapshot& snapshot) {
    size_t bytes = 0;
    for (const auto& item : snapshot) {
        if (item.first.size() > std::numeric_limits<size_t>::max() - bytes)
            return std::numeric_limits<size_t>::max();
        bytes += item.first.size();
        if (item.second.size() > std::numeric_limits<size_t>::max() - bytes)
            return std::numeric_limits<size_t>::max();
        bytes += item.second.size();
    }
    return bytes;
}

bool SnapshotWithinLimits(const RegistrySnapshot& snapshot,
                          const RegistrySnapshotLimits& limits,
                          size_t& payloadBytes) {
    if (snapshot.size() > limits.maxValuesPerTarget) return false;
    payloadBytes = SnapshotPayloadBytes(snapshot);
    return payloadBytes <= limits.maxPayloadBytesPerTarget;
}
} // namespace

RegistrySnapshotTracker::RegistrySnapshotTracker(RegistrySnapshotLimits limits)
    : m_limits(limits) {}

bool RegistrySnapshotTracker::Apply(
    const std::string& targetId, RegistrySnapshotStatus status,
    const RegistrySnapshot& candidate, bool dynamicTarget, bool emitChanges,
    std::vector<std::pair<std::string, std::string>>& changed,
    bool preserveMissing) {
    changed.clear();
    if (targetId.empty() || targetId.size() > kMaxRegistryNameCharacters ||
        status == RegistrySnapshotStatus::Failed) return false;
    if (preserveMissing && status == RegistrySnapshotStatus::Missing) return true;

    static const RegistrySnapshot kEmptySnapshot;
    const RegistrySnapshot& source = status == RegistrySnapshotStatus::Missing ?
        kEmptySnapshot : candidate;
    size_t payloadBytes = 0;
    if (!SnapshotWithinLimits(source, m_limits, payloadBytes)) return false;

    auto previous = m_targets.find(targetId);
    const bool isNew = previous == m_targets.end();
    const size_t previousValues = isNew ? 0 : previous->second.values.size();
    const size_t previousBytes = isNew ? 0 : previous->second.payloadBytes;
    const size_t retainedValues = m_totalValues - previousValues;
    const size_t retainedBytes = m_totalPayloadBytes - previousBytes;
    if (retainedValues > m_limits.maxTotalValues ||
        source.size() > m_limits.maxTotalValues - retainedValues ||
        retainedBytes > m_limits.maxTotalPayloadBytes ||
        payloadBytes > m_limits.maxTotalPayloadBytes - retainedBytes) return false;
    const size_t nextValues = retainedValues + source.size();
    const size_t nextBytes = retainedBytes + payloadBytes;
    size_t nextDynamic = 0;
    for (const auto& item : m_targets) {
        if (item.second.dynamic && item.first != targetId) ++nextDynamic;
    }
    if ((isNew && m_targets.size() >= m_limits.maxTargets) ||
        (dynamicTarget && isNew && nextDynamic >= m_limits.maxDynamicTargets) ||
        nextValues > m_limits.maxTotalValues ||
        nextBytes > m_limits.maxTotalPayloadBytes) return false;

    if (emitChanges && !isNew) {
        for (const auto& item : source) {
            const auto before = previous->second.values.find(item.first);
            if (before == previous->second.values.end() ||
                before->second != item.second) changed.push_back(item);
        }
    } else if (emitChanges && isNew && dynamicTarget) {
        changed.insert(changed.end(), source.begin(), source.end());
    }

    RetainedTarget retained;
    retained.values = source;
    retained.payloadBytes = payloadBytes;
    retained.dynamic = dynamicTarget;
    m_targets.insert_or_assign(targetId, std::move(retained));
    m_totalValues = nextValues;
    m_totalPayloadBytes = nextBytes;
    return true;
}

bool RegistrySnapshotTracker::ReconcileDynamicTargets(
    const std::set<std::string>& targetIds, bool enumerationComplete) {
    if (!enumerationComplete || targetIds.size() > m_limits.maxDynamicTargets)
        return false;
    size_t staticTargets = 0;
    for (const auto& item : m_targets)
        if (!item.second.dynamic) ++staticTargets;
    if (staticTargets > m_limits.maxTargets ||
        targetIds.size() > m_limits.maxTargets - staticTargets) return false;
    for (auto it = m_targets.begin(); it != m_targets.end();) {
        if (it->second.dynamic && targetIds.find(it->first) == targetIds.end()) {
            m_totalValues -= it->second.values.size();
            m_totalPayloadBytes -= it->second.payloadBytes;
            it = m_targets.erase(it);
        } else {
            ++it;
        }
    }
    return true;
}

bool RegistrySnapshotTracker::HasTarget(const std::string& targetId) const {
    return m_targets.find(targetId) != m_targets.end();
}

std::set<std::string> RegistrySnapshotTracker::KnownDynamicTargets() const {
    std::set<std::string> targets;
    for (const auto& item : m_targets)
        if (item.second.dynamic) targets.insert(item.first);
    return targets;
}

void RegistryWatchHealth::ConfigureTargets(size_t configured) noexcept {
    m_configuredTargets.store(configured);
}

void RegistryWatchHealth::RecordReadFailure() noexcept {
    m_readFailures.fetch_add(1);
}

void RegistryWatchHealth::RecordNotificationArmFailure() noexcept {
    m_notificationArmFailures.fetch_add(1);
}

void RegistryWatchHealth::PublishCoverage(
    size_t activeWatches, size_t missingTargets, size_t currentReadFailures,
    size_t currentArmFailures) noexcept {
    m_activeWatches.store(activeWatches);
    m_missingTargets.store(missingTargets);
    m_currentReadFailures.store(currentReadFailures);
    m_currentArmFailures.store(currentArmFailures);
}

CollectorHealthSnapshot RegistryWatchHealth::ApplyTo(
    CollectorHealthSnapshot sample) const {
    const uint64_t configured = m_configuredTargets.load();
    const uint64_t active = m_activeWatches.load();
    const uint64_t missing = m_missingTargets.load();
    const uint64_t currentReadFailures = m_currentReadFailures.load();
    const uint64_t currentArmFailures = m_currentArmFailures.load();
    sample.supported = true;
    if (sample.running) {
        if (currentReadFailures != 0 || currentArmFailures != 0 ||
            missing != 0 || active < configured) {
            sample.state = "degraded";
        }
    }
    sample.countersAvailable = true;
    sample.counters["configured_targets"] = configured;
    sample.counters["active_watches"] = active;
    sample.counters["missing_targets"] = missing;
    sample.counters["current_read_failures"] = currentReadFailures;
    sample.counters["current_notification_arm_failures"] = currentArmFailures;
    sample.counters["read_failures"] = m_readFailures.load();
    sample.counters["notification_arm_failures"] =
        m_notificationArmFailures.load();
    return sample;
}

RegistrySnapshotReadResult ReadRegistrySnapshotValuesChecked(
    HKEY key, const std::string& prefix,
    const std::vector<std::wstring>& valueFilter,
    const RegistrySnapshotLimits& limits) {
    RegistrySnapshotReadResult failed;
    if (!key || prefix.empty() || prefix.size() >= kMaxSnapshotEntryIdBytes)
        return failed;

    DWORD maxName = 0;
    if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr,
            nullptr, nullptr, &maxName, nullptr, nullptr, nullptr) !=
            ERROR_SUCCESS || maxName > kMaxRegistryNameCharacters) return failed;
    std::vector<wchar_t> name(static_cast<size_t>(maxName) + 2);
    std::vector<BYTE> data;
    RegistrySnapshot candidate;
    size_t payloadBytes = 0;
    size_t enumerated = 0;
    for (DWORD index = 0;;) {
        DWORD nameLen = static_cast<DWORD>(name.size());
        DWORD dataLen = 0;
        DWORD type = 0;
        LONG rc = RegEnumValueW(key, index, name.data(), &nameLen, nullptr,
                                &type, nullptr, &dataLen);
        if (rc == ERROR_NO_MORE_ITEMS) {
            RegistrySnapshotReadResult complete;
            complete.status = RegistrySnapshotStatus::Complete;
            complete.values = std::move(candidate);
            return complete;
        }
        if (++enumerated > limits.maxEnumeratedValues) return failed;
        if (rc == ERROR_MORE_DATA && nameLen >= name.size()) {
            if (nameLen > kMaxRegistryNameCharacters) return failed;
            name.resize(static_cast<size_t>(nameLen) + 2);
            continue;
        }
        if (rc != ERROR_SUCCESS || nameLen > kMaxRegistryNameCharacters)
            return failed;
        name[nameLen] = L'\0';
        if (ValueAccepted(valueFilter, name.data())) {
            const DWORD budget = RegistryTelemetryBudget(prefix, name.data());
            if (dataLen > budget) return failed;
            const std::string utf8Name = WideToUtf8(name.data(), nameLen);
            if (utf8Name.size() >= kMaxSnapshotEntryIdBytes - prefix.size() ||
                candidate.size() >= limits.maxValuesPerTarget) return failed;
            std::string id = prefix + "\\" + utf8Name;
            if (data.size() < static_cast<size_t>(dataLen) + sizeof(wchar_t))
                data.resize(static_cast<size_t>(dataLen) + sizeof(wchar_t));
            DWORD queried = dataLen;
            DWORD queriedType = type;
            if (!data.empty())
                std::fill(data.begin(), data.end(), static_cast<BYTE>(0));
            rc = RegQueryValueExW(key, name.data(), nullptr, &queriedType,
                                  data.empty() ? nullptr : data.data(), &queried);
            if (rc != ERROR_SUCCESS || queried > budget) return failed;
            std::string value;
            if (queriedType == REG_SZ || queriedType == REG_EXPAND_SZ) {
                const size_t chars = queried / sizeof(wchar_t);
                const auto* wide = reinterpret_cast<const wchar_t*>(data.data());
                size_t length = chars;
                while (length && wide[length - 1] == L'\0') --length;
                value = WideToUtf8(wide, length);
            } else {
                value = "<binary:" + std::to_string(queriedType) + ":" +
                    std::to_string(queried) + ">";
            }
            if (id.size() > std::numeric_limits<size_t>::max() - payloadBytes ||
                value.size() > std::numeric_limits<size_t>::max() -
                    payloadBytes - id.size()) return failed;
            payloadBytes += id.size() + value.size();
            if (payloadBytes > limits.maxPayloadBytesPerTarget) return failed;
            candidate.emplace(std::move(id), std::move(value));
        }
        ++index;
    }
}

void ReadRegistrySnapshotValues(HKEY key, const std::string& prefix,
        const std::vector<std::wstring>& valueFilter, RegistrySnapshot& out) {
    DWORD maxName = 0;
    if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr,
            nullptr, nullptr, &maxName, nullptr, nullptr, nullptr) !=
            ERROR_SUCCESS) return;
    std::vector<wchar_t> name(static_cast<size_t>(maxName) + 2);
    std::vector<BYTE> data(kMaxRegistryTelemetryBytes + sizeof(wchar_t), 0);
    for (DWORD i = 0;; ++i) {
        DWORD nameLen = static_cast<DWORD>(name.size());
        DWORD dataLen = 0;
        DWORD type = 0;
        LONG rc = RegEnumValueW(key, i, name.data(), &nameLen, nullptr, &type,
                                nullptr, &dataLen);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc == ERROR_MORE_DATA && nameLen >= name.size()) {
            name.resize(static_cast<size_t>(nameLen) + 2);
            --i;
            continue;
        }
        if (rc != ERROR_SUCCESS) continue;
        name[nameLen] = L'\0';
        if (!ValueAccepted(valueFilter, name.data())) continue;
        std::string id = prefix + "\\" + WideToUtf8(name.data(), nameLen);
        const DWORD budget = RegistryTelemetryBudget(prefix, name.data());
        if (dataLen > budget) {
            out[id] = "<truncated:" + std::to_string(type) + ":" +
                std::to_string(dataLen) + ">";
            continue;
        }
        if (data.size() < static_cast<size_t>(dataLen) + sizeof(wchar_t)) {
            data.resize(static_cast<size_t>(dataLen) + sizeof(wchar_t));
        }
        DWORD queried = dataLen;
        std::fill(data.begin(), data.end(), static_cast<BYTE>(0));
        rc = RegQueryValueExW(key, name.data(), nullptr, &type, data.data(),
                              &queried);
        if (rc == ERROR_MORE_DATA) {
            out[id] = "<truncated:" + std::to_string(type) + ":" +
                std::to_string(queried) + ">";
        } else if (rc != ERROR_SUCCESS) {
            continue;
        } else if (type == REG_SZ || type == REG_EXPAND_SZ) {
            size_t chars = queried / sizeof(wchar_t);
            const auto* wide = reinterpret_cast<const wchar_t*>(data.data());
            while (chars && wide[chars - 1] == L'\0') --chars;
            out[id] = WideToUtf8(wide, chars);
        } else {
            out[id] = "<binary:" + std::to_string(type) + ":" +
                std::to_string(queried) + ">";
        }
    }
}

struct RegWatchTarget {
    HKEY root;
    const wchar_t* subKey;
    const char* prefix;
    const wchar_t* const* valueFilter;
    size_t valueFilterCount;
    bool watchSubtree;
};

static const wchar_t* const kWinlogonFilter[] = { L"Shell", L"Userinit" };
static const wchar_t* const kIfeoFilter[] = { L"Debugger" };
static const wchar_t* const kWdigestFilter[] = { L"UseLogonCredential" };
static const wchar_t* const kSilentExitFilter[] = { L"MonitorProcess" };
/* Windows stores fDenyTSConnections / fSingleSessionPerUser under the
 * Terminal Server root key. UserAuthentication lives under
 * WinStations\RDP-Tcp and DisableRestrictedAdmin under Control\Lsa, so
 * they are separate targets below. */
static const wchar_t* const kRdpFilter[] = {
    L"fDenyTSConnections", L"fSingleSessionPerUser"
};
static const wchar_t* const kRdpTcpFilter[] = { L"UserAuthentication" };
static const wchar_t* const kLsaFilter[] = { L"DisableRestrictedAdmin" };
static const wchar_t* const kAlwaysInstallFilter[] = {
    L"AlwaysInstallElevated"
};

static const RegWatchTarget kTargets[] = {
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      nullptr, 0, false },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      nullptr, 0, false },
    { HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      nullptr, 0, false },
    { HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      nullptr, 0, false },
    { HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
      kWinlogonFilter, std::size(kWinlogonFilter), false },
    { HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
      kIfeoFilter, std::size(kIfeoFilter), true },
    { HKEY_LOCAL_MACHINE,
      L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
      "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
      kWdigestFilter, std::size(kWdigestFilter), false },
    { HKEY_LOCAL_MACHINE,
      L"SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp",
      "HKLM\\SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp",
      nullptr, 0, false },
    { HKEY_LOCAL_MACHINE,
      L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls",
      "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls",
      nullptr, 0, false },
    { HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",
      kSilentExitFilter, std::size(kSilentExitFilter), true },
    { HKEY_LOCAL_MACHINE,
      L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
      "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
      kRdpFilter, std::size(kRdpFilter), false },
    { HKEY_LOCAL_MACHINE,
      L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
      "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
      kRdpTcpFilter, std::size(kRdpTcpFilter), false },
    { HKEY_LOCAL_MACHINE,
      L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
      "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
      kLsaFilter, std::size(kLsaFilter), false },
    { HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
      "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
      kAlwaysInstallFilter, std::size(kAlwaysInstallFilter), false },
    { HKEY_CURRENT_USER,
      L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
      "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
      kAlwaysInstallFilter, std::size(kAlwaysInstallFilter), false },
    { HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Policies\\Google\\Chrome",
      "HKLM\\SOFTWARE\\Policies\\Google\\Chrome",
      nullptr, 0, true },
    { HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Policies\\Microsoft\\Edge",
      "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge",
      nullptr, 0, true },
    { HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Google\\Chrome\\Extensions",
      "HKLM\\SOFTWARE\\Google\\Chrome\\Extensions",
      nullptr, 0, true },
    { HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Microsoft\\Edge\\Extensions",
      "HKLM\\SOFTWARE\\Microsoft\\Edge\\Extensions",
      nullptr, 0, true },
    { HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\WOW6432Node\\Google\\Chrome\\Extensions",
      "HKLM\\SOFTWARE\\WOW6432Node\\Google\\Chrome\\Extensions",
      nullptr, 0, true },
    { HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\WOW6432Node\\Microsoft\\Edge\\Extensions",
      "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Edge\\Extensions",
      nullptr, 0, true },
};

/* The service runs as LocalSystem, so HKEY_CURRENT_USER does not represent
 * interactive users. Poll these shallow paths beneath every loaded HKU SID;
 * static notification targets still provide immediate wakeups where a root
 * already exists. */
static const wchar_t* const kUserBrowserRelativeKeys[] = {
    L"SOFTWARE\\Policies\\Google\\Chrome",
    L"SOFTWARE\\Policies\\Microsoft\\Edge",
    L"SOFTWARE\\Google\\Chrome\\Extensions",
    L"SOFTWARE\\Microsoft\\Edge\\Extensions",
};

constexpr size_t kMaxTargets = 32;
constexpr DWORD kTargetReopenIntervalMs = 2000;
static_assert(std::size(kTargets) <= kMaxTargets,
              "registry watcher target capacity is too small");

class RegWatchCollector : public ICollector {
public:
    RegWatchCollector() {
        m_registryHealth.ConfigureTargets(std::size(kTargets));
    }
    ~RegWatchCollector() override { Stop(); }

    CollectorHealthSnapshot GetHealthSnapshot() const override {
        return m_registryHealth.ApplyTo(m_runtimeHealth.Snapshot(
            m_workerFailed.load() ? "source_error" : "stopped"));
    }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) return true;
        if (!bus) return false;
        m_workerFailed.store(false);
        for (size_t i = 0; i < kMaxTargets; ++i) m_armFailed[i] = false;
        m_bus = bus;
        m_stop.store(false);

        m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!m_stopEvent) return false;

        m_keyCount = static_cast<int>(std::size(kTargets));
        for (int i = 0; i < m_keyCount; ++i) {
            m_handles[i] = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!m_handles[i]) {
                Stop();
                return false;
            }
            OpenTarget(i, true);
        }
        PublishCoverage(0, 0);

        try { m_thread = std::thread(&RegWatchCollector::Run, this); }
        catch (...) {
            Stop();
            return false;
        }
        return true;
    }

    void Stop() override {
        m_stop.store(true);
        if (m_stopEvent) SetEvent(m_stopEvent);
        if (m_thread.joinable()) m_thread.join();
        for (int i = 0; i < m_keyCount; i++) {
            CloseTarget(i);
            if (m_handles[i]) {
                CloseHandle(m_handles[i]);
                m_handles[i] = nullptr;
            }
        }
        m_keyCount = 0;
        PublishCoverage(0, 0);
        if (m_stopEvent) { CloseHandle(m_stopEvent); m_stopEvent = nullptr; }
        m_bus = nullptr;
    }

private:
    using Snapshot = RegistrySnapshot;

    bool ArmKey(int i) {
        if (!m_opened[i] || !m_handles[i]) return false;
        ResetEvent(m_handles[i]);
        const bool armed = RegNotifyChangeKeyValue(m_opened[i],
            kTargets[i].watchSubtree ? TRUE : FALSE,
            REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME,
            m_handles[i], TRUE) == ERROR_SUCCESS;
        if (armed) {
            m_armFailed[i] = false;
        } else {
            m_armFailed[i] = true;
            m_registryHealth.RecordNotificationArmFailure();
            m_runtimeHealth.RecordSourceError();
        }
        return armed;
    }

    void CloseTarget(int i) {
        if (m_handles[i]) ResetEvent(m_handles[i]);
        if (m_opened[i]) {
            RegCloseKey(m_opened[i]);
            m_opened[i] = nullptr;
        }
    }

    bool OpenTarget(int i, bool reportFailure) {
        if (m_opened[i]) return false;
        HKEY key = nullptr;
        const LONG openResult = RegOpenKeyExW(kTargets[i].root,
            kTargets[i].subKey, 0, KEY_READ | KEY_NOTIFY, &key);
        if (openResult != ERROR_SUCCESS) {
            const bool missing = openResult == ERROR_FILE_NOT_FOUND ||
                                 openResult == ERROR_PATH_NOT_FOUND;
            if (!missing) {
                m_runtimeHealth.RecordSourceError();
                m_registryHealth.RecordReadFailure();
            }
            if (reportFailure && !missing) {
                std::fprintf(stderr,
                    "[edr-regwatch] cannot open %s (error=%ld; will retry)\n",
                    kTargets[i].prefix, static_cast<long>(openResult));
            }
            return false;
        }
        m_opened[i] = key;
        if (!ArmKey(i)) {
            CloseTarget(i);
            return false;
        }
        return true;
    }

    bool OpenMissingTargets() {
        bool opened = false;
        for (int i = 0; i < m_keyCount; ++i) {
            if (!m_opened[i] && OpenTarget(i, false)) opened = true;
        }
        return opened;
    }

    static RegistrySnapshotReadResult ReadKey(const RegWatchTarget& target) {
        RegistrySnapshotReadResult failed;
        HKEY key = nullptr;
        const LONG openResult = RegOpenKeyExW(target.root, target.subKey, 0,
                                              KEY_READ, &key);
        if (openResult == ERROR_FILE_NOT_FOUND ||
            openResult == ERROR_PATH_NOT_FOUND) {
            failed.status = RegistrySnapshotStatus::Missing;
            return failed;
        }
        if (openResult != ERROR_SUCCESS) return failed;

        std::vector<std::wstring> filter;
        for (size_t i = 0; i < target.valueFilterCount; ++i)
            filter.emplace_back(target.valueFilter[i]);
        auto values = ReadRegistrySnapshotValuesChecked(
            key, target.prefix, filter);
        if (values.status != RegistrySnapshotStatus::Complete) {
            RegCloseKey(key);
            return failed;
        }
        Snapshot candidate = std::move(values.values);
        if (target.watchSubtree) {
            /* One level of subkeys (e.g. IFEO\<image>) flattened into ids. */
            DWORD maxSubKey = 0;
            if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr,
                    &maxSubKey, nullptr, nullptr, nullptr, nullptr, nullptr,
                    nullptr) != ERROR_SUCCESS ||
                maxSubKey > kMaxRegistryNameCharacters) {
                RegCloseKey(key);
                return failed;
            }
            std::vector<wchar_t> name(static_cast<size_t>(maxSubKey) + 2);
            size_t enumerated = 0;
            for (DWORD i = 0;;) {
                DWORD nameLen = 0;
                LONG rc = ERROR_SUCCESS;
                do {
                    nameLen = static_cast<DWORD>(name.size());
                    rc = RegEnumKeyExW(key, i, name.data(), &nameLen,
                                       nullptr, nullptr, nullptr, nullptr);
                    if (rc == ERROR_MORE_DATA) {
                        if (nameLen > kMaxRegistryNameCharacters) {
                            RegCloseKey(key);
                            return failed;
                        }
                        size_t required = static_cast<size_t>(nameLen) + 2;
                        const size_t doubled = std::min(
                            name.size() * 2,
                            static_cast<size_t>(kMaxRegistryNameCharacters) + 2);
                        name.resize(std::max(required, doubled));
                    }
                } while (rc == ERROR_MORE_DATA);
                if (rc == ERROR_NO_MORE_ITEMS) break;
                if (++enumerated > 4096) {
                    RegCloseKey(key);
                    return failed;
                }
                if (rc != ERROR_SUCCESS || nameLen > kMaxRegistryNameCharacters) {
                    RegCloseKey(key);
                    return failed;
                }
                name[nameLen] = L'\0';
                HKEY child = nullptr;
                if (RegOpenKeyExW(key, name.data(), 0, KEY_READ, &child) !=
                    ERROR_SUCCESS) {
                    RegCloseKey(key);
                    return failed;
                }
                std::string childPrefix =
                    std::string(target.prefix) + "\\" + WideToUtf8(name.data(), nameLen);
                auto childValues = ReadRegistrySnapshotValuesChecked(
                    child, childPrefix, filter);
                RegCloseKey(child);
                const size_t maxValues =
                    RegistrySnapshotLimits{}.maxValuesPerTarget;
                if (childValues.status != RegistrySnapshotStatus::Complete ||
                    candidate.size() > maxValues ||
                    childValues.values.size() > maxValues - candidate.size()) {
                    RegCloseKey(key);
                    return failed;
                }
                size_t candidatePayload = 0;
                size_t childPayload = 0;
                const RegistrySnapshotLimits limits;
                if (!SnapshotWithinLimits(candidate, limits, candidatePayload) ||
                    !SnapshotWithinLimits(childValues.values, limits, childPayload) ||
                    childPayload > limits.maxPayloadBytesPerTarget -
                        candidatePayload) {
                    RegCloseKey(key);
                    return failed;
                }
                candidate.insert(childValues.values.begin(),
                                 childValues.values.end());
                ++i;
            }
        }
        RegCloseKey(key);
        RegistrySnapshotReadResult complete;
        complete.status = RegistrySnapshotStatus::Complete;
        complete.values = std::move(candidate);
        size_t payload = 0;
        if (!SnapshotWithinLimits(complete.values, RegistrySnapshotLimits{}, payload))
            return failed;
        return complete;
    }

    static bool EnumerateLoadedUserBrowserTargets(std::set<std::string>& out) {
        out.clear();
        DWORD maxSubKey = 0;
        if (RegQueryInfoKeyW(HKEY_USERS, nullptr, nullptr, nullptr, nullptr,
                &maxSubKey, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr) != ERROR_SUCCESS ||
            maxSubKey > kMaxRegistryNameCharacters) return false;

        std::vector<wchar_t> name(static_cast<size_t>(maxSubKey) + 2);
        size_t scanned = 0;
        size_t sidCount = 0;
        for (DWORD i = 0;;) {
            DWORD nameLen = 0;
            LONG rc = ERROR_SUCCESS;
            do {
                nameLen = static_cast<DWORD>(name.size());
                rc = RegEnumKeyExW(HKEY_USERS, i, name.data(), &nameLen,
                                   nullptr, nullptr, nullptr, nullptr);
                if (rc == ERROR_MORE_DATA) {
                    if (nameLen > kMaxRegistryNameCharacters) return false;
                    const size_t required = static_cast<size_t>(nameLen) + 2;
                    const size_t doubled = std::min(
                        name.size() * 2,
                        static_cast<size_t>(kMaxRegistryNameCharacters) + 2);
                    name.resize(std::max(required, doubled));
                }
            } while (rc == ERROR_MORE_DATA);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (++scanned > 1024) return false;
            if (rc != ERROR_SUCCESS || nameLen > kMaxRegistryNameCharacters)
                return false;
            name[nameLen] = L'\0';

            const std::wstring sid(name.data(), nameLen);
            if (sid.rfind(L"S-", 0) != 0) { ++i; continue; }
            if (sid.size() > 184) return false;
            if (sid.size() >= 8 &&
                _wcsicmp(sid.c_str() + sid.size() - 8, L"_Classes") == 0) {
                ++i;
                continue;
            }
            if (++sidCount > 512) return false;

            for (const wchar_t* relative : kUserBrowserRelativeKeys) {
                out.insert("HKU\\" + WideToUtf8(sid.c_str()) + "\\" +
                           WideToUtf8(relative));
            }
            ++i;
        }
        return out.size() <= RegistrySnapshotLimits{}.maxDynamicTargets;
    }

    static std::wstring Utf8SubKey(const std::string& targetId) {
        if (targetId.size() <= 4 || targetId.compare(0, 4, "HKU\\") != 0)
            return {};
        const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            targetId.data() + 4, static_cast<int>(targetId.size() - 4),
            nullptr, 0);
        if (count <= 0 || count > static_cast<int>(kMaxRegistryNameCharacters))
            return {};
        std::wstring result(static_cast<size_t>(count), L'\0');
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                targetId.data() + 4, static_cast<int>(targetId.size() - 4),
                result.data(), count) != count) return {};
        return result;
    }

    RegistrySnapshotReadResult ReadDynamicTarget(const std::string& targetId) {
        const std::wstring subKey = Utf8SubKey(targetId);
        if (subKey.empty()) return {};
        const RegWatchTarget target = {
            HKEY_USERS, subKey.c_str(), targetId.c_str(), nullptr, 0, true
        };
        return ReadKey(target);
    }

    void EmitChanges(
        const std::vector<std::pair<std::string, std::string>>& changed) {
        for (const auto& item : changed) {
            Event ev;
            ev.type = EDR_EVT_REG_WRITE;
            ev.source = "registry_watch";
            ev.fields[field::kSource] = ev.source;
            FILETIME ft;
            GetSystemTimePreciseAsFileTime(&ft);
            ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) |
                         ft.dwLowDateTime;
            ev.fields[field::kType] = "REG_WRITE";
            ev.fields[field::kRegKey] = item.first;
            ev.fields[field::kRegValue] = item.second;
            ev.fields[field::kRegOperation] = "SnapshotChange";
            if (m_bus) {
                const bool overflowObserved = !m_bus->Push(ev);
                m_runtimeHealth.RecordEventSubmitted(overflowObserved);
            }
        }
    }

    bool ApplyResult(const std::string& targetId, bool dynamicTarget,
                     const RegistrySnapshotReadResult& result,
                     bool emitChanges, size_t& cycleReadFailures,
                     size_t& cycleMissingTargets,
                     bool preserveMissing = false) {
        if (result.status == RegistrySnapshotStatus::Failed) {
            ++cycleReadFailures;
            m_registryHealth.RecordReadFailure();
            m_runtimeHealth.RecordSourceError();
            return false;
        }
        if (result.status == RegistrySnapshotStatus::Missing)
            ++cycleMissingTargets;
        std::vector<std::pair<std::string, std::string>> changed;
        if (!m_tracker.Apply(targetId, result.status, result.values,
                             dynamicTarget, emitChanges, changed,
                             preserveMissing)) {
            ++cycleReadFailures;
            m_registryHealth.RecordReadFailure();
            m_runtimeHealth.RecordSourceError();
            return false;
        }
        EmitChanges(changed);
        return true;
    }

    size_t ActiveWatchCount() const {
        size_t active = 0;
        for (int i = 0; i < m_keyCount; ++i)
            if (m_opened[i]) ++active;
        return active;
    }

    size_t CurrentArmFailureCount() const {
        size_t failed = 0;
        for (int i = 0; i < m_keyCount; ++i)
            if (m_armFailed[i]) ++failed;
        return failed;
    }

    void PublishCoverage(size_t missingTargets, size_t currentReadFailures) {
        m_lastMissingTargets = missingTargets;
        const size_t armFailures = CurrentArmFailureCount();
        m_registryHealth.PublishCoverage(ActiveWatchCount(), missingTargets,
                                         currentReadFailures, armFailures);
    }

    void SampleAll(bool emitChanges) {
        size_t cycleReadFailures = 0;
        size_t cycleMissingTargets = 0;
        for (size_t i = 0; i < std::size(kTargets); ++i) {
            const auto result = ReadKey(kTargets[i]);
            ApplyResult(kTargets[i].prefix, false, result, emitChanges,
                        cycleReadFailures, cycleMissingTargets);
        }

        std::set<std::string> enumeratedTargets;
        const bool enumerationComplete =
            EnumerateLoadedUserBrowserTargets(enumeratedTargets);
        std::set<std::string> targetsToRead;
        if (enumerationComplete && m_tracker.ReconcileDynamicTargets(
                enumeratedTargets, true)) {
            targetsToRead = std::move(enumeratedTargets);
        } else {
            ++cycleReadFailures;
            m_registryHealth.RecordReadFailure();
            m_runtimeHealth.RecordSourceError();
            targetsToRead = m_tracker.KnownDynamicTargets();
        }
        for (const auto& targetId : targetsToRead) {
            const auto result = ReadDynamicTarget(targetId);
            ApplyResult(targetId, true, result, emitChanges,
                        cycleReadFailures, cycleMissingTargets,
                        !enumerationComplete);
        }

        PublishCoverage(cycleMissingTargets, cycleReadFailures);
        if (cycleReadFailures == 0 && CurrentArmFailureCount() == 0)
            m_runtimeHealth.RecordSnapshotSuccess();
    }

    void Run() {
        m_runtimeHealth.WorkerStarted();
        struct WorkerStopped {
            CollectorRuntimeHealth& health;
            ~WorkerStopped() { health.WorkerStopped(); }
        } workerStopped{m_runtimeHealth};
        try {
            bool initialSample = true;
            SampleAll(false);
            initialSample = false;

            HANDLE waitHandles[kMaxTargets + 1] = {};
            waitHandles[0] = m_stopEvent;
            for (int i = 0; i < m_keyCount; i++)
                waitHandles[i + 1] = m_handles[i];
            int totalHandles = 1 + m_keyCount;

            while (!m_stop.load()) {
                DWORD wait = WaitForMultipleObjects(
                    totalHandles, waitHandles, FALSE, kTargetReopenIntervalMs);
                if (wait == WAIT_OBJECT_0) break;
                if (wait == WAIT_TIMEOUT) {
                    OpenMissingTargets();
                    SampleAll(!initialSample);
                    continue;
                }
                if (wait == WAIT_FAILED) {
                    m_runtimeHealth.RecordSourceError();
                    m_registryHealth.RecordReadFailure();
                    PublishCoverage(m_lastMissingTargets, 1);
                    Sleep(1000);
                    continue;
                }
                if (wait > WAIT_OBJECT_0 &&
                    wait < WAIT_OBJECT_0 + (DWORD)totalHandles) {
                    int idx = (int)(wait - WAIT_OBJECT_0 - 1);
                    if (!ArmKey(idx)) CloseTarget(idx);
                    OpenMissingTargets();
                    SampleAll(!initialSample);
                }
            }
        } catch (...) {
            m_workerFailed.store(true);
            m_runtimeHealth.RecordSourceError();
            m_registryHealth.RecordReadFailure();
            PublishCoverage(m_lastMissingTargets, 1);
        }
    }

    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    HANDLE m_stopEvent = nullptr;
    HANDLE m_handles[kMaxTargets] = {};
    HKEY m_opened[kMaxTargets] = {};
    bool m_armFailed[kMaxTargets] = {};
    int m_keyCount = 0;
    RegistrySnapshotTracker m_tracker;
    RegistryWatchHealth m_registryHealth;
    CollectorRuntimeHealth m_runtimeHealth;
    size_t m_lastMissingTargets = 0; // worker-owned; health reads use atomics only
    std::atomic<bool> m_workerFailed{false};
};

ICollector* CreateRegWatchCollector() { return new RegWatchCollector(); }

const std::vector<RegWatchTargetSummary>& RegWatchTargetSummaries() {
    static const std::vector<RegWatchTargetSummary> summaries = [] {
        std::vector<RegWatchTargetSummary> out;
        out.reserve(std::size(kTargets));
        for (const RegWatchTarget& target : kTargets) {
            RegWatchTargetSummary summary;
            summary.prefix = target.prefix;
            summary.watchSubtree = target.watchSubtree;
            for (size_t i = 0; i < target.valueFilterCount; ++i)
                summary.valueNames.push_back(
                    WideToUtf8(target.valueFilter[i]));
            out.push_back(std::move(summary));
        }
        return out;
    }();
    return summaries;
}

} // namespace edr
