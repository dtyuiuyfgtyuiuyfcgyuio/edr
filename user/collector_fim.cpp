/*
 * collector_fim.cpp - File integrity monitoring collector.
 *
 * Each configured path keeps its last conclusive observation across polling
 * failures. Only GetFileReputation's same-handle identity and digest are used
 * for a complete snapshot; oversized files are reported as uncovered health.
 */
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <map>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "collector.h"
#include "collector_fim.h"
#include "collector_runtime_health.h"
#include "edr_event.h"
#include "file_reputation.h"

namespace edr {
namespace {

constexpr size_t kMaxWatchFiles = 256;
constexpr size_t kMaxWatchPathBytes = 32768;
constexpr size_t kMaxWatchPathBytesTotal = 1024 * 1024;

struct FileBaseline {
    uint64_t size = 0;
    std::string sha256;
    bool present = false;
    bool known = false;
};

bool ValidWatchFiles(const std::vector<std::string>& paths) {
    if (paths.empty() || paths.size() > kMaxWatchFiles) return false;
    size_t totalBytes = 0;
    for (const auto& path : paths) {
        if (path.empty() || path.size() > kMaxWatchPathBytes ||
            path.find('\0') != std::string::npos ||
            path.size() > kMaxWatchPathBytesTotal - totalBytes) {
            return false;
        }
        totalBytes += path.size();
        const int wideLength = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            path.data(), static_cast<int>(path.size()), nullptr, 0);
        if (wideLength <= 0) return false;
    }
    return true;
}

bool IsSha256(const std::string& value) {
    if (value.size() != 64) return false;
    for (char ch : value) {
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
              (ch >= 'A' && ch <= 'F'))) return false;
    }
    return true;
}

FimSnapshot QueryFileReputation(const std::string& utf8Path,
                                uint64_t maxFileBytes) {
    FimSnapshot snapshot;
    const int wideLength = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        utf8Path.data(), static_cast<int>(utf8Path.size()), nullptr, 0);
    if (wideLength <= 0) {
        snapshot.statusCode = GetLastError();
        return snapshot;
    }
    std::wstring widePath(static_cast<size_t>(wideLength), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8Path.data(),
        static_cast<int>(utf8Path.size()), &widePath[0], wideLength) != wideLength) {
        snapshot.statusCode = GetLastError();
        return snapshot;
    }

    FileReputationSettings settings;
    settings.enabled = true;
    settings.maxFileBytes = maxFileBytes;
    settings.cacheOnlyTrust = true;
    const FileReputationResult reputation = GetFileReputation(widePath, settings);
    snapshot.statusCode = reputation.statusCode;
    if (reputation.status == FileReputationStatus::OpenError &&
        (reputation.statusCode == ERROR_FILE_NOT_FOUND ||
         reputation.statusCode == ERROR_PATH_NOT_FOUND)) {
        snapshot.status = FimSnapshotStatus::Missing;
    } else if (reputation.status == FileReputationStatus::Complete &&
               reputation.sha256.size() == 64) {
        snapshot.status = FimSnapshotStatus::Complete;
        snapshot.size = reputation.identity.size;
        snapshot.sha256 = reputation.sha256;
    } else {
        snapshot.status = FimSnapshotStatus::Failed;
        snapshot.oversized = reputation.status == FileReputationStatus::FileTooLarge;
        if (snapshot.oversized) snapshot.size = reputation.identity.size;
    }
    return snapshot;
}

} // namespace

class FimCollector : public ICollector {
public:
    FimCollector(uint32_t pollMs, uint64_t maxFileBytes,
                 std::vector<std::string> watchFiles, FimSnapshotQuery query)
        : m_pollMs(std::max<uint32_t>(pollMs, 10)),
          m_maxFileBytes(maxFileBytes), m_watchFiles(std::move(watchFiles)),
          m_query(std::move(query)), m_validWatchFiles(ValidWatchFiles(m_watchFiles)) {}

    ~FimCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) return !m_workerFailed.load();
        if (bus == nullptr) return false;
        m_explicitStop.store(false);
        if (!m_validWatchFiles) return false;
        m_bus = bus;
        m_stop.store(false);
        m_explicitStop.store(false);
        m_workerFailed.store(false);
        m_failedWatchFiles.store(0);
        m_oversizedWatchFiles.store(0);
        try {
            m_thread = std::thread(&FimCollector::Run, this);
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
        const uint64_t failed = m_failedWatchFiles.load();
        const uint64_t oversized = m_oversizedWatchFiles.load();
        sample.counters["watch_files_configured"] = m_watchFiles.size();
        sample.counters["watch_files_failed_current"] = failed;
        sample.counters["watch_files_oversized_uncovered_current"] = oversized;
        sample.counters["watch_paths_valid"] = m_validWatchFiles ? 1 : 0;
        const auto successfulSnapshots = sample.counters.find("successful_snapshots");
        const bool observed = successfulSnapshots != sample.counters.end() &&
                              successfulSnapshots->second != 0;
        sample.counters["source_available"] =
            sample.running && observed && m_validWatchFiles && !m_workerFailed.load() &&
            failed == 0 && oversized == 0 ? 1 : 0;
        if (!m_explicitStop.load() && !m_validWatchFiles) sample.state = "config_error";
        else if (!m_explicitStop.load() && m_workerFailed.load()) sample.state = "source_error";
        else if (sample.running && failed != 0) sample.state = "source_error";
        else if (sample.running && oversized != 0) sample.state = "coverage_degraded";
        return sample;
    }

private:
    FimSnapshot SnapshotFile(const std::string& utf8Path) const {
        FimSnapshot snapshot = m_query ? m_query(utf8Path, m_maxFileBytes) :
                                         QueryFileReputation(utf8Path, m_maxFileBytes);
        switch (snapshot.status) {
        case FimSnapshotStatus::Complete:
            if (snapshot.statusCode == ERROR_SUCCESS && !snapshot.oversized &&
                snapshot.size <= m_maxFileBytes && IsSha256(snapshot.sha256)) {
                return snapshot;
            }
            break;
        case FimSnapshotStatus::Missing:
            if ((snapshot.statusCode == ERROR_FILE_NOT_FOUND ||
                 snapshot.statusCode == ERROR_PATH_NOT_FOUND) &&
                snapshot.size == 0 && snapshot.sha256.empty() && !snapshot.oversized) {
                return snapshot;
            }
            break;
        case FimSnapshotStatus::Failed:
            if (snapshot.oversized &&
                snapshot.statusCode == ERROR_FILE_TOO_LARGE &&
                snapshot.size > m_maxFileBytes && snapshot.sha256.empty()) {
                return snapshot;
            }
            break;
        default:
            break;
        }
        snapshot.status = FimSnapshotStatus::Failed;
        snapshot.oversized = false;
        snapshot.sha256.clear();
        return snapshot;
    }

    void Emit(const std::string& path, const char* action,
              const FileBaseline& baseline) {
        Event ev;
        ev.type = EDR_EVT_FILE_INTEGRITY;
        ev.source = "fim_monitor";
        FILETIME ft = {};
        GetSystemTimePreciseAsFileTime(&ft);
        ev.ts100ns = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) |
                     ft.dwLowDateTime;
        ev.fields[field::kSource] = ev.source;
        ev.fields[field::kType] = "FILE_INTEGRITY";
        ev.fields[field::kFimAction] = action;
        ev.fields[field::kFimPath] = path;
        if (baseline.present) {
            ev.fields[field::kFimSize] = std::to_string(baseline.size);
            if (!baseline.sha256.empty())
                ev.fields[field::kFimSha256] = baseline.sha256;
        }
        ev.fields[field::kFimBaseline] = baseline.known ? "true" : "false";
        if (m_bus != nullptr) m_health.RecordEventSubmitted(!m_bus->Push(ev));
    }

    void Run() noexcept {
        m_health.WorkerStarted();
        try {
            std::map<std::string, FileBaseline> baseline;
            while (!m_stop.load()) {
                uint64_t failed = 0;
                uint64_t oversized = 0;
                for (const auto& path : m_watchFiles) {
                    if (m_stop.load()) break;
                    FimSnapshot now = SnapshotFile(path);
                    if (m_stop.load()) break;
                    if (now.status == FimSnapshotStatus::Failed) {
                        if (now.oversized) ++oversized;
                        else ++failed;
                        continue; // A failed/partial query must retain a valid baseline.
                    }

                    const bool present = now.status == FimSnapshotStatus::Complete;
                    FileBaseline observed;
                    observed.known = true;
                    observed.present = present;
                    if (present) {
                        observed.size = now.size;
                        observed.sha256 = std::move(now.sha256);
                    }

                    auto existing = baseline.find(path);
                    if (existing == baseline.end()) {
                        baseline.emplace(path, std::move(observed));
                    } else {
                        const FileBaseline& before = existing->second;
                        if (before.present && !present) {
                            Emit(path, "removed", before);
                        } else if (!before.present && present) {
                            Emit(path, "added", observed);
                        } else if (before.present && present &&
                            (before.size != observed.size ||
                             before.sha256 != observed.sha256)) {
                            Emit(path, "modified", observed);
                        }
                        existing->second = std::move(observed);
                    }
                }
                m_failedWatchFiles.store(failed);
                m_oversizedWatchFiles.store(oversized);
                if (failed == 0) m_health.RecordSnapshotSuccess();
                else m_health.RecordSourceError(failed);

                uint32_t remaining = m_pollMs;
                while (remaining != 0 && !m_stop.load()) {
                    const uint32_t delay = std::min<uint32_t>(remaining, 100);
                    Sleep(delay);
                    remaining -= delay;
                }
            }
        } catch (...) {
            m_workerFailed.store(true);
            m_failedWatchFiles.store(m_watchFiles.size());
            m_health.RecordSourceError();
        }
        m_health.WorkerStopped();
    }

    uint32_t m_pollMs;
    uint64_t m_maxFileBytes;
    std::vector<std::string> m_watchFiles;
    FimSnapshotQuery m_query;
    const bool m_validWatchFiles;
    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_explicitStop{true};
    std::atomic<bool> m_workerFailed{false};
    std::atomic<uint64_t> m_failedWatchFiles{0};
    std::atomic<uint64_t> m_oversizedWatchFiles{0};
    CollectorRuntimeHealth m_health;
};

ICollector* CreateFimCollector(uint32_t pollMs, uint64_t maxFileBytes,
                               std::vector<std::string> watchFiles) {
    return new FimCollector(pollMs, maxFileBytes, std::move(watchFiles), {});
}

ICollector* CreateFimCollector(uint32_t pollMs, uint64_t maxFileBytes,
                               std::vector<std::string> watchFiles,
                               FimSnapshotQuery query) {
    return new FimCollector(pollMs, maxFileBytes, std::move(watchFiles),
                            std::move(query));
}

} // namespace edr
