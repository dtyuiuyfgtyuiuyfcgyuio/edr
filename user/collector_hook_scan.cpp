/*
 * collector_hook_scan.cpp - Periodic hook persistence surface scanner.
 */
#include "collector_hook_scan.h"

#include <algorithm>
#include <limits>
#include <utility>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {
namespace {

constexpr size_t kMaxRegistryNameChars = 16383;
constexpr size_t kMapNodeChargeBytes = 256;
constexpr unsigned kMaxSnapshotAttempts = 3;

class RegistryKey {
public:
    RegistryKey() = default;
    explicit RegistryKey(HKEY key) : m_key(key) {}
    ~RegistryKey() { if (m_key) RegCloseKey(m_key); }
    RegistryKey(const RegistryKey&) = delete;
    RegistryKey& operator=(const RegistryKey&) = delete;
    RegistryKey(RegistryKey&& other) noexcept : m_key(other.m_key) {
        other.m_key = nullptr;
    }
    RegistryKey& operator=(RegistryKey&& other) noexcept {
        if (this != &other) {
            if (m_key) RegCloseKey(m_key);
            m_key = other.m_key;
            other.m_key = nullptr;
        }
        return *this;
    }
    HKEY get() const { return m_key; }
private:
    HKEY m_key = nullptr;
};

bool WideToUtf8Strict(const wchar_t* value, size_t chars, std::string& out) {
    out.clear();
    if (chars == 0) return true;
    if (chars > static_cast<size_t>((std::numeric_limits<int>::max)())) return false;
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
        static_cast<int>(chars), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return false;
    out.resize(static_cast<size_t>(size));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
        static_cast<int>(chars), &out[0], size, nullptr, nullptr) == size;
}

bool ValidUtf8TargetId(const std::string& value) {
    if (value.empty() || value.size() > 64 * 1024 ||
        value.find('\0') != std::string::npos ||
        value.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
        return false;
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0) > 0;
}

bool ReadStringValue(HKEY key, const wchar_t* valueName, size_t maxValueBytes,
                     std::string& utf8, bool& missing) {
    missing = false;
    utf8.clear();
    DWORD type = 0;
    DWORD bytes = 0;
    LONG rc = RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes);
    if (rc == ERROR_FILE_NOT_FOUND) { missing = true; return true; }
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) ||
        bytes > maxValueBytes || bytes % sizeof(wchar_t) != 0) return false;
    std::vector<BYTE> data(static_cast<size_t>(bytes) + sizeof(wchar_t), 0);
    for (unsigned attempt = 0; attempt < kMaxSnapshotAttempts; ++attempt) {
        DWORD queried = static_cast<DWORD>(data.size() - sizeof(wchar_t));
        DWORD queriedType = 0;
        rc = RegQueryValueExW(key, valueName, nullptr, &queriedType,
                              data.data(), &queried);
        if (rc == ERROR_MORE_DATA) {
            if (queried > maxValueBytes || queried % sizeof(wchar_t) != 0)
                return false;
            data.assign(static_cast<size_t>(queried) + sizeof(wchar_t), 0);
            continue;
        }
        if (rc != ERROR_SUCCESS || queriedType != type ||
            queried > maxValueBytes || queried % sizeof(wchar_t) != 0)
            return false;
        size_t chars = queried / sizeof(wchar_t);
        const auto* wide = reinterpret_cast<const wchar_t*>(data.data());
        while (chars && wide[chars - 1] == L'\0') --chars;
        for (size_t i = 0; i < chars; ++i)
            if (wide[i] == L'\0') return false;
        return WideToUtf8Strict(wide, chars, utf8);
    }
    return false;
}

bool ReadTarget(HKEY root, const std::wstring& targetName,
                const std::string& prefix, HookScanSurface surface,
                const HookScanReadLimits& limits, HookScanTargetSnapshot& out) {
    out = {};
    out.status = HookScanSnapshotStatus::Failed;
    if (targetName.empty() || targetName.size() > kMaxRegistryNameChars)
        return false;
    std::string utf8Target;
    if (!WideToUtf8Strict(targetName.data(), targetName.size(), utf8Target) ||
        utf8Target.empty()) return false;
    size_t payloadBytes = 0;
    auto add = [&](const std::string& path, const std::string& value) {
        if (path.size() > limits.maxTargetPayloadBytes - payloadBytes ||
            value.size() > limits.maxTargetPayloadBytes - payloadBytes - path.size())
            return false;
        payloadBytes += path.size() + value.size();
        out.values.emplace(path, value);
        return true;
    };

    if (surface == HookScanSurface::Ifeo) {
        RegistryKey target;
        HKEY opened = nullptr;
        if (RegOpenKeyExW(root, targetName.c_str(), 0, KEY_READ, &opened) !=
            ERROR_SUCCESS) return false;
        target = RegistryKey(opened);
        FILETIME before = {};
        FILETIME after = {};
        if (RegQueryInfoKeyW(target.get(), nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &before) !=
            ERROR_SUCCESS) return false;
        std::string value;
        bool missing = false;
        if (!ReadStringValue(target.get(), L"Debugger", limits.maxValueBytes,
                             value, missing))
            return false;
        if (RegQueryInfoKeyW(target.get(), nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &after) !=
            ERROR_SUCCESS || CompareFileTime(&before, &after) != 0) return false;
        if (!missing && !value.empty() &&
            !add(prefix + "\\" + utf8Target + "\\Debugger", value))
            return false;
    } else {
        const wchar_t* const servers[] = {L"InprocServer32", L"LocalServer32"};
        RegistryKey clsid;
        HKEY clsidOpened = nullptr;
        if (RegOpenKeyExW(root, targetName.c_str(), 0, KEY_READ,
                          &clsidOpened) != ERROR_SUCCESS) return false;
        clsid = RegistryKey(clsidOpened);
        DWORD subkeysBefore = 0;
        FILETIME clsidBefore = {};
        if (RegQueryInfoKeyW(clsid.get(), nullptr, nullptr, nullptr,
                &subkeysBefore, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, &clsidBefore) != ERROR_SUCCESS) return false;
        for (const wchar_t* server : servers) {
            RegistryKey target;
            HKEY opened = nullptr;
            const std::wstring path = targetName + L"\\" + server;
            const LONG openRc = RegOpenKeyExW(root, path.c_str(), 0, KEY_READ,
                                               &opened);
            if (openRc == ERROR_FILE_NOT_FOUND || openRc == ERROR_PATH_NOT_FOUND)
                continue;
            if (openRc != ERROR_SUCCESS) return false;
            target = RegistryKey(opened);
            FILETIME before = {};
            FILETIME after = {};
            if (RegQueryInfoKeyW(target.get(), nullptr, nullptr, nullptr,
                    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                    nullptr, &before) != ERROR_SUCCESS) return false;
            std::string value;
            bool missing = false;
            if (!ReadStringValue(target.get(), nullptr, limits.maxValueBytes,
                                 value, missing))
                return false;
            if (RegQueryInfoKeyW(target.get(), nullptr, nullptr, nullptr,
                    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                    nullptr, &after) != ERROR_SUCCESS ||
                CompareFileTime(&before, &after) != 0) return false;
            if (!missing && !value.empty()) {
                std::string serverUtf8;
                if (!WideToUtf8Strict(server, wcslen(server), serverUtf8) ||
                    !add(prefix + "\\" + utf8Target + "\\" + serverUtf8,
                         value)) return false;
            }
        }
        DWORD subkeysAfter = 0;
        FILETIME clsidAfter = {};
        if (RegQueryInfoKeyW(clsid.get(), nullptr, nullptr, nullptr,
                &subkeysAfter, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, &clsidAfter) != ERROR_SUCCESS ||
            subkeysBefore != subkeysAfter ||
            CompareFileTime(&clsidBefore, &clsidAfter) != 0) return false;
    }
    out.status = HookScanSnapshotStatus::Complete;
    return true;
}

HookScanRootSnapshot ReadRootOnce(HKEY hive, const std::wstring& rootPath,
        const std::string& prefix, HookScanSurface surface, size_t maxTargets,
        const HookScanReadLimits& limits) {
    HookScanRootSnapshot failed;
    failed.status = HookScanSnapshotStatus::Failed;
    HKEY opened = nullptr;
    const LONG openRc = RegOpenKeyExW(hive, rootPath.c_str(), 0, KEY_READ,
                                      &opened);
    if (openRc == ERROR_FILE_NOT_FOUND || openRc == ERROR_PATH_NOT_FOUND) {
        HookScanRootSnapshot missing;
        missing.status = HookScanSnapshotStatus::Missing;
        return missing;
    }
    if (openRc != ERROR_SUCCESS) return failed;
    RegistryKey root(opened);
    DWORD subkeys = 0;
    DWORD maxName = 0;
    FILETIME before = {};
    if (RegQueryInfoKeyW(root.get(), nullptr, nullptr, nullptr, &subkeys,
            &maxName, nullptr, nullptr, nullptr, nullptr, nullptr, &before) !=
        ERROR_SUCCESS || subkeys > maxTargets || subkeys > limits.maxTargets ||
        maxName > kMaxRegistryNameChars)
        return failed;

    HookScanRootSnapshot candidate;
    candidate.status = HookScanSnapshotStatus::Complete;
    size_t rootPayloadBytes = 0;
    std::vector<wchar_t> name(static_cast<size_t>(std::max<DWORD>(maxName, 1)) + 2);
    for (DWORD index = 0; index < subkeys; ++index) {
        DWORD nameLength = static_cast<DWORD>(name.size());
        FILETIME childWrite = {};
        LONG rc = RegEnumKeyExW(root.get(), index, name.data(), &nameLength,
                                nullptr, nullptr, nullptr, &childWrite);
        if (rc == ERROR_MORE_DATA) {
            if (nameLength > kMaxRegistryNameChars) return failed;
            name.resize(static_cast<size_t>(nameLength) + 2);
            nameLength = static_cast<DWORD>(name.size());
            rc = RegEnumKeyExW(root.get(), index, name.data(), &nameLength,
                               nullptr, nullptr, nullptr, &childWrite);
        }
        if (rc != ERROR_SUCCESS || nameLength > kMaxRegistryNameChars)
            return failed;
        const std::wstring targetName(name.data(), nameLength);
        std::string targetUtf8;
        if (!WideToUtf8Strict(targetName.data(), targetName.size(), targetUtf8) ||
            targetUtf8.empty()) return failed;
        HookScanTargetSnapshot target;
        if (!ReadTarget(root.get(), targetName, prefix, surface, limits, target)) {
            target.values.clear();
            target.status = HookScanSnapshotStatus::Failed;
        }
        size_t targetCharge = targetUtf8.size();
        if (targetCharge > SIZE_MAX - kMapNodeChargeBytes) return failed;
        targetCharge += kMapNodeChargeBytes;
        for (const auto& value : target.values) {
            if (value.first.size() > SIZE_MAX - value.second.size()) return failed;
            const size_t valueCharge = value.first.size() + value.second.size();
            if (valueCharge > SIZE_MAX - kMapNodeChargeBytes ||
                valueCharge + kMapNodeChargeBytes > SIZE_MAX - targetCharge)
                return failed;
            targetCharge += valueCharge + kMapNodeChargeBytes;
        }
        if (rootPayloadBytes > limits.maxRootPayloadBytes ||
            targetCharge > limits.maxRootPayloadBytes - rootPayloadBytes)
            return failed;
        rootPayloadBytes += targetCharge;
        candidate.targets.emplace(targetUtf8, std::move(target));
    }
    DWORD afterSubkeys = 0;
    FILETIME after = {};
    if (RegQueryInfoKeyW(root.get(), nullptr, nullptr, nullptr, &afterSubkeys,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &after) !=
        ERROR_SUCCESS || afterSubkeys != subkeys ||
        CompareFileTime(&before, &after) != 0) return failed;
    return candidate;
}

} // namespace

size_t EstimateHookScanTargetCharge(const std::string& targetId,
        const HookScanValues& values, size_t* componentsExamined) {
    if (componentsExamined) *componentsExamined = 1;
    if (targetId.size() > SIZE_MAX - kMapNodeChargeBytes) return SIZE_MAX;
    size_t bytes = targetId.size() + kMapNodeChargeBytes;
    for (const auto& value : values) {
        if (componentsExamined && *componentsExamined != SIZE_MAX)
            ++*componentsExamined;
        if (value.first.size() > SIZE_MAX - value.second.size()) return SIZE_MAX;
        const size_t valueBytes = value.first.size() + value.second.size();
        if (valueBytes > SIZE_MAX - kMapNodeChargeBytes ||
            valueBytes + kMapNodeChargeBytes > SIZE_MAX - bytes) return SIZE_MAX;
        bytes += valueBytes + kMapNodeChargeBytes;
    }
    return bytes;
}

HookScanRetainedBudget::HookScanRetainedBudget(HookScanBudgetLimits limits)
    : m_limits(limits) {}

bool HookScanRetainedBudget::Set(const std::string& targetId,
        HookScanValues values,
        std::vector<std::pair<std::string, std::string>>* changed,
        bool emitNew) {
    if (changed) changed->clear();
    size_t components = 0;
    const size_t charge = EstimateHookScanTargetCharge(targetId, values, &components);
    if (components > SIZE_MAX - m_candidateItemsExamined)
        m_candidateItemsExamined = SIZE_MAX;
    else m_candidateItemsExamined += components;
    if (charge == SIZE_MAX || !ValidUtf8TargetId(targetId)) return false;
    for (const auto& value : values)
        if (!ValidUtf8TargetId(value.first) ||
            (!value.second.empty() && !ValidUtf8TargetId(value.second))) return false;
    const auto old = m_targets.find(targetId);
    const size_t oldValues = old == m_targets.end() ? 0 : old->second.values.size();
    const size_t oldCharge = old == m_targets.end() ? 0 : old->second.charge;
    const size_t retainedValues = m_values - oldValues;
    const size_t retainedBytes = m_bytes - oldCharge;
    if ((old == m_targets.end() && m_targets.size() >= m_limits.maxTargets) ||
        retainedValues > m_limits.maxValues ||
        values.size() > m_limits.maxValues - retainedValues ||
        retainedBytes > m_limits.maxBytes || charge > m_limits.maxBytes - retainedBytes)
        return false;
    const bool reportInitialValues =
        (old == m_targets.end() && emitNew) ||
        (old != m_targets.end() && !old->second.known &&
         old->second.emitOnRecovery);
    if (changed && old != m_targets.end() && old->second.known) {
        for (const auto& value : values) {
            const auto prior = old->second.values.find(value.first);
            if (prior == old->second.values.end() || prior->second != value.second)
                changed->push_back(value);
        }
    } else if (changed && reportInitialValues) {
        changed->insert(changed->end(), values.begin(), values.end());
    }
    Entry entry;
    entry.values = std::move(values);
    entry.charge = charge;
    entry.known = true;
    m_targets.insert_or_assign(targetId, std::move(entry));
    m_values = retainedValues + m_targets.find(targetId)->second.values.size();
    m_bytes = retainedBytes + charge;
    return true;
}

bool HookScanRetainedBudget::SetUnknown(const std::string& targetId,
        bool emitOnRecovery) {
    size_t components = 0;
    const size_t charge = EstimateHookScanTargetCharge(targetId, {}, &components);
    if (components > SIZE_MAX - m_candidateItemsExamined)
        m_candidateItemsExamined = SIZE_MAX;
    else m_candidateItemsExamined += components;
    if (charge == SIZE_MAX || !ValidUtf8TargetId(targetId)) return false;
    const auto old = m_targets.find(targetId);
    if (old != m_targets.end()) return true;
    if (m_targets.size() >= m_limits.maxTargets ||
        m_values > m_limits.maxValues || m_bytes > m_limits.maxBytes ||
        charge > m_limits.maxBytes - m_bytes) return false;
    Entry entry;
    entry.charge = charge;
    entry.known = false;
    entry.emitOnRecovery = emitOnRecovery;
    m_targets.emplace(targetId, std::move(entry));
    m_bytes += charge;
    return true;
}

bool HookScanRetainedBudget::Erase(const std::string& targetId) {
    const auto found = m_targets.find(targetId);
    if (found == m_targets.end()) return false;
    m_values -= found->second.values.size();
    m_bytes -= found->second.charge;
    m_targets.erase(found);
    return true;
}

void HookScanRetainedBudget::ErasePrefix(const std::string& prefix,
        const std::atomic<bool>* stop) {
    for (auto it = m_targets.begin(); it != m_targets.end();) {
        if (stop && stop->load()) return;
        if (it->first.compare(0, prefix.size(), prefix) == 0) {
            m_values -= it->second.values.size();
            m_bytes -= it->second.charge;
            it = m_targets.erase(it);
        } else ++it;
    }
}

void HookScanRetainedBudget::EraseAbsent(const std::string& prefix,
        const std::map<std::string, HookScanTargetSnapshot>& present,
        const std::atomic<bool>* stop) {
    for (auto it = m_targets.begin(); it != m_targets.end();) {
        if (stop && stop->load()) return;
        if (it->first.compare(0, prefix.size(), prefix) != 0) { ++it; continue; }
        const std::string name = it->first.substr(prefix.size());
        const auto found = present.find(name);
        if (found != present.end() &&
            found->second.status != HookScanSnapshotStatus::Missing) {
            ++it;
            continue;
        }
        m_values -= it->second.values.size();
        m_bytes -= it->second.charge;
        it = m_targets.erase(it);
    }
}

const HookScanValues* HookScanRetainedBudget::Find(
        const std::string& targetId) const {
    const auto found = m_targets.find(targetId);
    return found == m_targets.end() ? nullptr : &found->second.values;
}

HookScanRootSnapshot ReadHookScanRegistryRoot(HKEY hive,
        const std::wstring& rootPath, const std::string& utf8Prefix,
        HookScanSurface surface, size_t maxTargets,
        const HookScanReadLimits& limits) {
    if (hive == nullptr || rootPath.empty() || utf8Prefix.empty() ||
        maxTargets == 0 || maxTargets > limits.maxTargets ||
        limits.maxValueBytes > 16 * 1024 * 1024 ||
        limits.maxTargetPayloadBytes > 16 * 1024 * 1024 ||
        limits.maxRootPayloadBytes > 64 * 1024 * 1024) return {};
    for (unsigned attempt = 0; attempt < kMaxSnapshotAttempts; ++attempt) {
        HookScanRootSnapshot result = ReadRootOnce(hive, rootPath, utf8Prefix,
                                                    surface, maxTargets, limits);
        if (result.status != HookScanSnapshotStatus::Failed ||
            attempt + 1 == kMaxSnapshotAttempts) return result;
    }
    return {};
}

HookScanCollector::HookScanCollector(uint32_t pollSeconds, size_t maxEntries)
    : HookScanCollector(pollSeconds, maxEntries, {}) {}

HookScanCollector::HookScanCollector(uint32_t pollSeconds, size_t maxEntries,
                                     HookScanQuery query)
    : m_pollMs((pollSeconds ? pollSeconds : 600) > UINT32_MAX / 1000u ?
          UINT32_MAX : (pollSeconds ? pollSeconds : 600) * 1000u),
      m_maxEntries((std::min)(maxEntries ? maxEntries : 1024,
                            HookScanBudgetLimits{}.maxTargets)),
      m_query(std::move(query)) {}

HookScanCollector::~HookScanCollector() { Stop(); }

bool HookScanCollector::Start(EventBus* bus) {
    if (m_thread.joinable()) {
        if (!m_workerFailed.load()) return true;
        m_thread.join();
    }
    if (bus == nullptr) return false;
    m_bus = bus;
    m_stop.store(false);
    m_explicitStop.store(false);
    m_workerFailed.store(false);
    m_failedCurrent.store(0);
    m_missingCurrent.store(0);
    m_pendingCurrent.store(1);
    m_successesAtStart.store(m_health.Snapshot().counters["successful_snapshots"]);
    try {
        m_thread = std::thread(&HookScanCollector::ScanAndDiff, this);
    } catch (...) {
        m_stop.store(true);
        m_workerFailed.store(true);
        m_health.RecordSourceError();
        m_bus = nullptr;
        return false;
    }
    return true;
}

void HookScanCollector::Stop() {
    m_explicitStop.store(true);
    m_stop.store(true);
    if (m_thread.joinable()) m_thread.join();
    m_bus = nullptr;
}

CollectorHealthSnapshot HookScanCollector::GetHealthSnapshot() const {
    CollectorHealthSnapshot sample = m_health.Snapshot(
        !m_explicitStop.load() && m_workerFailed.load() ? "source_error" : "stopped");
    const uint64_t failed = m_failedCurrent.load();
    const uint64_t missing = m_missingCurrent.load();
    sample.counters["targets_failed_current"] = failed;
    sample.counters["roots_missing_current"] = missing;
    sample.counters["targets_pending_current"] = m_pendingCurrent.load();
    const auto successes = sample.counters.find("successful_snapshots");
    const bool sampled = successes != sample.counters.end() &&
        successes->second > m_successesAtStart.load();
    sample.counters["source_available"] = sample.running && sampled && failed == 0 &&
        missing == 0 && m_pendingCurrent.load() == 0 && !m_workerFailed.load() ? 1 : 0;
    if (!m_explicitStop.load() && m_workerFailed.load()) sample.state = "source_error";
    else if (sample.running && failed != 0) sample.state = "source_error";
    else if (sample.running && missing != 0) sample.state = "coverage_degraded";
    else if (sample.running && !sampled) sample.state = "starting";
    return sample;
}

void HookScanCollector::ScanAndDiff() {
    m_health.WorkerStarted();
    HookScanRetainedBudget retained;
    bool ifeoObserved = false;
    bool comObserved = false;
    try {
        for (;;) {
            if (m_stop.load()) break;
            HookScanSnapshot snapshot;
            if (m_query) snapshot = m_query();
            else {
                snapshot.ifeo = ReadHookScanRegistryRoot(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                    HookScanSurface::Ifeo, m_maxEntries);
                snapshot.hkcuCom = ReadHookScanRegistryRoot(HKEY_CURRENT_USER,
                    L"SOFTWARE\\Classes\\CLSID", "HKCU\\SOFTWARE\\Classes\\CLSID",
                    HookScanSurface::HkcuCom, m_maxEntries);
            }
            if (m_stop.load()) break;

            size_t failures = 0;
            size_t missingRoots = 0;
            size_t pending = 0;
            auto commitRoot = [&](const char* rootId,
                                  const HookScanRootSnapshot& root) {
                bool& observed = std::string(rootId) == "ifeo" ?
                    ifeoObserved : comObserved;
                if (root.status != HookScanSnapshotStatus::Complete &&
                    root.status != HookScanSnapshotStatus::Missing &&
                    root.status != HookScanSnapshotStatus::Failed) {
                    ++failures;
                    ++pending;
                    return;
                }
                if (root.status == HookScanSnapshotStatus::Failed) {
                    ++failures;
                    ++pending;
                    return;
                }
                if (root.status == HookScanSnapshotStatus::Missing) {
                    ++missingRoots;
                    retained.ErasePrefix(std::string(rootId) + "\\", &m_stop);
                    if (!m_stop.load()) observed = true;
                    return;
                }
                if (root.targets.size() > m_maxEntries) {
                    ++failures;
                    ++pending;
                    return;
                }
                const std::string prefix = std::string(rootId) + "\\";
                for (const auto& item : root.targets) {
                    if (m_stop.load()) return;
                    if (!ValidUtf8TargetId(item.first)) {
                        ++failures;
                        ++pending;
                        return; // reject the root before reconciling absent targets
                    }
                    if (item.second.status != HookScanSnapshotStatus::Complete &&
                        item.second.status != HookScanSnapshotStatus::Missing &&
                        item.second.status != HookScanSnapshotStatus::Failed) {
                        ++failures;
                        ++pending;
                        return;
                    }
                }
                retained.EraseAbsent(prefix, root.targets, &m_stop);
                if (m_stop.load()) return;
                bool initialUnknownNotRetained = false;
                auto rememberUnknown = [&](const std::string& targetId) {
                    if (retained.SetUnknown(targetId, observed)) return;
                    ++failures;
                    ++pending;
                    if (!observed) initialUnknownNotRetained = true;
                };
                for (const auto& item : root.targets) {
                    if (m_stop.load()) return;
                    const std::string targetId = std::string(rootId) + "\\" + item.first;
                    if (item.second.status == HookScanSnapshotStatus::Failed) {
                        ++failures;
                        ++pending;
                        rememberUnknown(targetId);
                        continue;
                    }
                    if (item.second.status == HookScanSnapshotStatus::Missing) {
                        retained.Erase(targetId);
                        continue;
                    }
                    if (item.second.status != HookScanSnapshotStatus::Complete) {
                        ++failures;
                        ++pending;
                        continue;
                    }
                    if (item.second.values.size() > 2) {
                        ++failures;
                        ++pending;
                        rememberUnknown(targetId);
                        continue;
                    }
                    bool valuesValid = true;
                    for (const auto& value : item.second.values) {
                        if (!ValidUtf8TargetId(value.first) ||
                            (!value.second.empty() && !ValidUtf8TargetId(value.second)))
                            valuesValid = false;
                    }
                    if (!valuesValid) {
                        ++failures;
                        ++pending;
                        rememberUnknown(targetId);
                        continue;
                    }
                    {
                        std::vector<std::pair<std::string, std::string>> changed;
                        if (!retained.Set(targetId, item.second.values, &changed,
                                          observed)) {
                            ++failures;
                            ++pending;
                            rememberUnknown(targetId);
                            continue;
                        }
                        if (m_bus != nullptr) {
                            for (const auto& value : changed) {
                                if (m_stop.load()) return;
                                Event event;
                                event.type = EDR_EVT_REG_WRITE;
                                event.source = "hook_scan";
                                FILETIME now = {};
                                GetSystemTimePreciseAsFileTime(&now);
                                event.ts100ns = (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
                                                now.dwLowDateTime;
                                event.fields[field::kSource] = event.source;
                                event.fields[field::kType] = "REG_WRITE";
                                event.fields[field::kRegKey] = value.first;
                                event.fields[field::kRegValue] = value.second;
                                if (!m_bus->Push(event)) m_health.RecordEventSubmitted(true);
                                else m_health.RecordEventSubmitted(false);
                            }
                        }
                    }
                }
                if (!m_stop.load() &&
                    (observed || !initialUnknownNotRetained)) observed = true;
            };
            commitRoot("ifeo", snapshot.ifeo);
            if (m_stop.load()) break;
            commitRoot("com", snapshot.hkcuCom);
            if (m_stop.load()) break;

            m_failedCurrent.store(failures);
            m_missingCurrent.store(missingRoots);
            m_pendingCurrent.store(pending);
            if (failures == 0) m_health.RecordSnapshotSuccess();
            else m_health.RecordSourceError(failures);

            uint32_t remaining = m_pollMs;
            while (remaining != 0 && !m_stop.load()) {
                const uint32_t delay = std::min<uint32_t>(remaining, 100);
                Sleep(delay);
                remaining -= delay;
            }
            if (m_stop.load()) break;
        }
    } catch (...) {
        m_workerFailed.store(true);
        m_failedCurrent.store(1);
        m_pendingCurrent.store(1);
        m_health.RecordSourceError();
    }
    m_health.WorkerStopped();
}

ICollector* CreateHookScanCollector(uint32_t pollSeconds, size_t maxEntries) {
    return new HookScanCollector(pollSeconds, maxEntries);
}

ICollector* CreateHookScanCollector(uint32_t pollSeconds, size_t maxEntries,
                                    HookScanQuery query) {
    return new HookScanCollector(pollSeconds, maxEntries, std::move(query));
}

} // namespace edr
