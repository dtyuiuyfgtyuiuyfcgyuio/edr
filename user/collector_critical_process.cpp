/*
 * collector_critical_process.cpp - Critical security process protection.
 *
 * A complete Toolhelp snapshot is required before a poll can change a
 * protected image's missing or recovery state. Failed and partial reads are
 * reported through collector health and leave that state untouched.
 */
#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <condition_variable>
#include <cstdio>
#include <climits>
#include <cwchar>
#include <cwctype>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "collector.h"
#include "collector_critical_process.h"
#include "collector_runtime_health.h"
#include "config.h"
#include "edr_event.h"

namespace edr {
namespace {

constexpr size_t kMaximumConfiguredImages = 256;
constexpr size_t kMaximumConfiguredNameBytes = 1024;
constexpr size_t kMaximumNativeImageCharacters = MAX_PATH;

std::string Lower(std::string value) {
    for (char& ch : value)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return value;
}

bool ValidUtf8Name(const std::string& value) {
    return !value.empty() && value.size() <= kMaximumConfiguredNameBytes &&
        value.find('\0') == std::string::npos &&
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), nullptr, 0) > 0;
}

bool WideToUtf8Checked(const wchar_t* value, size_t length,
                       std::string& output) {
    output.clear();
    if (!value || length == 0 || length > kMaximumNativeImageCharacters ||
        length > static_cast<size_t>(INT_MAX)) return false;
    const int characters = static_cast<int>(length);
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        value, characters, nullptr, 0, nullptr, nullptr);
    if (bytes <= 0 || bytes > static_cast<int>(kMaximumConfiguredNameBytes))
        return false;
    output.resize(static_cast<size_t>(bytes));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
        characters, output.data(), bytes, nullptr, nullptr) == bytes &&
        output.find('\0') == std::string::npos;
}

bool NativeImageName(const PROCESSENTRY32W& entry, std::string& output) {
    const size_t length = wcsnlen_s(entry.szExeFile, MAX_PATH);
    if (length == 0 || length == MAX_PATH) return false;
    std::wstring lower(entry.szExeFile, length);
    for (wchar_t& ch : lower) ch = static_cast<wchar_t>(towlower(ch));
    size_t slash = lower.find_last_of(L"\\/");
    const std::wstring base = slash == std::wstring::npos
        ? lower : lower.substr(slash + 1);
    return WideToUtf8Checked(base.data(), base.size(), output);
}

struct SnapshotCloser {
    const CriticalProcessToolhelpApi* api = nullptr;
    HANDLE handle = INVALID_HANDLE_VALUE;
    ~SnapshotCloser() {
        if (api && api->close && handle != nullptr &&
            handle != INVALID_HANDLE_VALUE) {
            try { api->close(handle); } catch (...) {}
        }
    }
};

bool ValidCompleteSnapshot(const CriticalProcessSnapshot& snapshot) {
    if (snapshot.status != CriticalProcessSnapshotStatus::Complete ||
        snapshot.images.size() > 65536) return false;
    for (const std::string& image : snapshot.images)
        if (!ValidUtf8Name(image)) return false;
    return true;
}

class CriticalProcessCollector final : public ICollector {
public:
    CriticalProcessCollector(uint32_t pollMs, uint32_t missingThreshold,
        std::vector<std::string> protectedImages, CriticalProcessQuery query)
        : m_pollMs(std::max<uint32_t>(pollMs, 1)),
          m_missingThreshold(std::max<uint32_t>(missingThreshold, 1)),
          m_query(std::move(query)) {
        if (!CriticalProcessConfigIsValid(protectedImages)) return;
        for (std::string& image : protectedImages)
            m_protectedImages.push_back(Lower(std::move(image)));
        std::sort(m_protectedImages.begin(), m_protectedImages.end());
        m_protectedImages.erase(std::unique(m_protectedImages.begin(),
            m_protectedImages.end()), m_protectedImages.end());
        m_configValid = !m_protectedImages.empty() && static_cast<bool>(m_query);
    }

    ~CriticalProcessCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (bus == nullptr || !m_configValid) return false;
        if (m_thread.joinable()) return m_active.load();
        m_bus = bus;
        m_stop.store(false);
        m_fatal.store(false);
        m_stopped.store(false);
        m_health.ResetSourceState();
        m_active.store(true);
        try {
            m_thread = std::thread(&CriticalProcessCollector::Run, this);
        } catch (...) {
            m_active.store(false);
            m_fatal.store(true);
            m_health.RecordSourceError();
            m_bus = nullptr;
            return false;
        }
        return true;
    }

    void Stop() override {
        m_stop.store(true);
        m_wake.notify_all();
        if (m_thread.joinable()) m_thread.join();
        m_bus = nullptr;
        m_stopped.store(true);
        if (m_emitCount.load() != 0 || m_health.Snapshot().sourceErrors != 0) {
            const auto health = m_health.Snapshot();
            std::fprintf(stderr,
                "[edr-critical-process] emitted=%llu source_errors=%llu\n",
                static_cast<unsigned long long>(m_emitCount.load()),
                static_cast<unsigned long long>(health.sourceErrors));
        }
    }

    CollectorHealthSnapshot GetHealthSnapshot() const override {
        return m_health.Snapshot(
            m_fatal.load() && !m_stopped.load() ? "source_error" : "stopped");
    }

private:
    void Emit(const std::string& image, const char* action,
              const char* reason) {
        Event ev;
        ev.type = EDR_EVT_CRITICAL_PROCESS;
        ev.source = "critical_process_monitor";
        FILETIME ft = {};
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) |
                     ft.dwLowDateTime;
        ev.fields[field::kSource] = ev.source;
        ev.fields[field::kType] = "CRITICAL_PROCESS";
        ev.fields[field::kCriticalProcessAction] = action;
        ev.fields[field::kCriticalProcessImage] = image;
        if (reason != nullptr) ev.fields[field::kCriticalProcessReason] = reason;
        if (m_bus != nullptr)
            m_health.RecordEventSubmitted(!m_bus->Push(ev));
        ++m_emitCount;
    }

    void Run() noexcept {
        m_health.WorkerStarted();
        try {
            std::map<std::string, uint32_t> missingCount;
            std::set<std::string> reportedMissing;
            for (const std::string& image : m_protectedImages)
                missingCount.emplace(image, 0);

            while (!m_stop.load()) {
                const CriticalProcessSnapshot snapshot = m_query();
                if (m_stop.load()) break;
                if (ValidCompleteSnapshot(snapshot)) {
                    m_health.RecordSnapshotSuccess();
                    for (const std::string& image : m_protectedImages) {
                        if (snapshot.images.count(image) != 0) {
                            if (reportedMissing.erase(image) != 0) {
                                Emit(image, "recovered",
                                     "critical process detected again");
                            }
                            missingCount[image] = 0;
                        } else if (!reportedMissing.count(image)) {
                            uint32_t& count = missingCount[image];
                            if (count < m_missingThreshold) ++count;
                            if (count >= m_missingThreshold) {
                                Emit(image, "terminated", "critical process missing");
                                reportedMissing.insert(image);
                            }
                        }
                    }
                } else {
                    m_health.RecordSourceError();
                }

                std::unique_lock<std::mutex> lock(m_waitMutex);
                m_wake.wait_for(lock, std::chrono::milliseconds(m_pollMs),
                    [this] { return m_stop.load(); });
            }
        } catch (...) {
            m_fatal.store(true);
            m_health.RecordSourceError();
        }
        m_active.store(false);
        m_health.WorkerStopped();
    }

    uint32_t m_pollMs;
    uint32_t m_missingThreshold;
    std::vector<std::string> m_protectedImages;
    CriticalProcessQuery m_query;
    bool m_configValid = false;
    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_active{false};
    std::atomic<bool> m_fatal{false};
    std::atomic<bool> m_stopped{true};
    std::atomic<uint64_t> m_emitCount{0};
    mutable CollectorRuntimeHealth m_health;
    std::mutex m_waitMutex;
    std::condition_variable m_wake;
};

} // namespace

CriticalProcessToolhelpApi CriticalProcessToolhelpApi::Native() {
    CriticalProcessToolhelpApi api;
    api.createSnapshot = [] {
        return CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    };
    api.first = [](HANDLE handle, LPPROCESSENTRY32W entry) {
        return Process32FirstW(handle, entry);
    };
    api.next = [](HANDLE handle, LPPROCESSENTRY32W entry) {
        return Process32NextW(handle, entry);
    };
    api.lastError = [] { return GetLastError(); };
    api.close = [](HANDLE handle) { CloseHandle(handle); };
    return api;
}

CriticalProcessSnapshot ReadCriticalProcessSnapshot(
    const CriticalProcessToolhelpApi& api, size_t maxProcesses) {
    if (!api.createSnapshot || !api.first || !api.next ||
        !api.lastError || !api.close || maxProcesses == 0) return {};

    HANDLE handle = api.createSnapshot();
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) return {};
    SnapshotCloser close{&api, handle};

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (!api.first(handle, &entry)) {
        if (api.lastError() == ERROR_NO_MORE_FILES)
            return {CriticalProcessSnapshotStatus::Complete, {}};
        return {};
    }

    CriticalProcessSnapshot snapshot;
    snapshot.status = CriticalProcessSnapshotStatus::Complete;
    size_t enumerated = 0;
    for (;;) {
        if (enumerated >= maxProcesses) return {};
        ++enumerated;
        std::string image;
        if (!NativeImageName(entry, image)) return {};
        snapshot.images.insert(std::move(image));

        entry = {};
        entry.dwSize = sizeof(entry);
        if (!api.next(handle, &entry)) {
            if (api.lastError() == ERROR_NO_MORE_FILES) return snapshot;
            return {};
        }
    }
}

bool CriticalProcessConfigIsValid(const std::vector<std::string>& images) {
    if (images.empty() || images.size() > kMaximumConfiguredImages) return false;
    for (const std::string& image : images) {
        if (!ValidUtf8Name(image) || image.find_first_of("/\\") !=
            std::string::npos) return false;
    }
    return true;
}

ICollector* CreateCriticalProcessCollector(
    uint32_t pollMs, uint32_t missingThreshold,
    const std::vector<std::string>& protectedImages) {
    return CreateCriticalProcessCollector(pollMs, missingThreshold,
        protectedImages, [] {
            return ReadCriticalProcessSnapshot(CriticalProcessToolhelpApi::Native());
        });
}

ICollector* CreateCriticalProcessCollector(
    uint32_t pollMs, uint32_t missingThreshold,
    const std::vector<std::string>& protectedImages,
    CriticalProcessQuery query) {
    return new CriticalProcessCollector(pollMs, missingThreshold,
        protectedImages, std::move(query));
}

} // namespace edr
