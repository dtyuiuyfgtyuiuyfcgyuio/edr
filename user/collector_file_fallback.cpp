/*
 * collector_file_fallback.cpp - ReadDirectoryChangesW based FILE_CREATE
 * source for configurable directories (default %TEMP% and
 * \Users\Public\Downloads).
 *
 * Blind spot (documented in README): directory change notifications carry
 * no process attribution, so FILE_CREATE events from this source have no
 * pid/image fields (missing-field semantics M3 apply to rules).
 */
#include <windows.h>

#include <atomic>
#include <cstddef>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#include "collector.h"
#include "collector_runtime_health.h"
#include "config.h"
#include "edr_event.h"

namespace edr {

class FileFallbackCollector : public ICollector {
public:
    explicit FileFallbackCollector(std::vector<std::string> dirs)
        : m_dirs(std::move(dirs)) {}

    ~FileFallbackCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) {
            return true;
        }
        m_bus = bus;
        m_stop.store(false);
        m_noActiveWatches.store(false);
        m_watchSetupComplete.store(false);
        m_activeWatches.store(0);
        m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (m_stopEvent == nullptr) {
            m_health.RecordSourceError();
            std::fprintf(stderr,
                         "EDR file collector: CreateEvent failed (%lu)\n",
                         GetLastError());
            return false;
        }
        try {
            m_thread = std::thread(&FileFallbackCollector::Run, this);
        } catch (...) {
            m_health.RecordSourceError();
            CloseHandle(m_stopEvent);
            m_stopEvent = nullptr;
            m_stop.store(true);
            m_bus = nullptr;
            return false;
        }
        return true;
    }

    void Stop() override {
        m_stop.store(true);
        if (m_stopEvent != nullptr) {
            SetEvent(m_stopEvent);
        }
        if (m_thread.joinable()) {
            m_thread.join();
        }
        if (m_stopEvent != nullptr) {
            CloseHandle(m_stopEvent);
            m_stopEvent = nullptr;
        }
    }

private:
    struct Watch {
        HANDLE dir = nullptr;
        OVERLAPPED ov = {};
        std::vector<uint8_t> buffer;
        std::string root; /* UTF-8 */
        bool pending = false;
    };

    void Run() {
        m_health.WorkerStarted();
        struct ActivityGuard {
            CollectorRuntimeHealth& health;
            ~ActivityGuard() { health.WorkerStopped(); }
        } activity{m_health};
        std::vector<Watch> watches(m_dirs.size());
        std::vector<HANDLE> events{m_stopEvent};
        std::vector<Watch*> activeWatches; /* aligned with events[1..] */

        for (size_t i = 0; i < m_dirs.size(); i++) {
            if (events.size() == MAXIMUM_WAIT_OBJECTS) {
                m_health.RecordSourceError();
                std::fprintf(stderr,
                             "EDR file collector: too many watch directories; "
                             "maximum is %lu\n",
                             (unsigned long)(MAXIMUM_WAIT_OBJECTS - 1));
                break;
            }
            Watch& w = watches[i];
            w.root = m_dirs[i];
            w.buffer.resize(64 * 1024);
            std::wstring wide = Utf8ToWide(m_dirs[i]);
            w.dir = CreateFileW(wide.c_str(), FILE_LIST_DIRECTORY,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                                nullptr);
            if (w.dir == INVALID_HANDLE_VALUE) {
                m_health.RecordSourceError();
                w.dir = nullptr;
                continue;
            }
            w.ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (w.ov.hEvent == nullptr) {
                m_health.RecordSourceError();
                std::fprintf(stderr,
                             "EDR file collector: watch event creation "
                             "failed for %s (%lu)\n",
                             w.root.c_str(), GetLastError());
                CloseHandle(w.dir);
                w.dir = nullptr;
                continue;
            }
            events.push_back(w.ov.hEvent);
            activeWatches.push_back(&w);
        }

        for (size_t i = activeWatches.size(); i > 0; --i) {
            Watch* watch = activeWatches[i - 1];
            if (!Arm(*watch)) {
                CloseHandle(watch->ov.hEvent);
                CloseHandle(watch->dir);
                watch->ov.hEvent = nullptr;
                watch->dir = nullptr;
                activeWatches.erase(activeWatches.begin() + (i - 1));
                events.erase(events.begin() + i);
            } else {
                watch->pending = true;
            }
        }
        m_activeWatches.store(activeWatches.size());
        if (!activeWatches.empty()) m_health.RecordSnapshotSuccess();
        if (activeWatches.empty()) m_noActiveWatches.store(true);
        m_watchSetupComplete.store(true);

        while (!m_stop.load() && !activeWatches.empty()) {
            DWORD wait = WaitForMultipleObjects((DWORD)events.size(),
                                                events.data(), FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0) {
                break;
            }
            if (wait < WAIT_OBJECT_0 + 1 ||
                wait >= WAIT_OBJECT_0 + events.size()) {
                m_health.RecordSourceError();
                break;
            }
            size_t index = (size_t)(wait - WAIT_OBJECT_0 - 1);
            Watch& w = *activeWatches[index];
            DWORD bytes = 0;
            if (GetOverlappedResult(w.dir, &w.ov, &bytes, FALSE)) {
                if (bytes > 0) {
                    m_health.RecordSnapshotSuccess();
                    Drain(w, bytes);
                }
            } else if (GetLastError() != ERROR_OPERATION_ABORTED &&
                       !m_stop.load()) {
                m_health.RecordSourceError();
            }
            w.pending = false;
            if (!m_stop.load()) {
                w.pending = Arm(w);
                if (!w.pending) {
                    CloseHandle(w.ov.hEvent);
                    CloseHandle(w.dir);
                    w.ov.hEvent = nullptr;
                    w.dir = nullptr;
                    activeWatches.erase(activeWatches.begin() + index);
                    events.erase(events.begin() + index + 1);
                    m_activeWatches.store(activeWatches.size());
                }
            }
        }

        m_activeWatches.store(0);
        if (!m_stop.load()) m_noActiveWatches.store(true);

        for (auto& w : watches) {
            if (w.dir != nullptr) {
                if (w.pending) {
                    DWORD bytes = 0;
                    CancelIoEx(w.dir, &w.ov);
                    GetOverlappedResult(w.dir, &w.ov, &bytes, TRUE);
                    w.pending = false;
                }
                if (w.ov.hEvent != nullptr) {
                    CloseHandle(w.ov.hEvent);
                    w.ov.hEvent = nullptr;
                }
                CloseHandle(w.dir);
                w.dir = nullptr;
            }
        }
    }

    bool Arm(Watch& w) {
        ResetEvent(w.ov.hEvent);
        DWORD bytes = 0;
        if (ReadDirectoryChangesW(
                w.dir, w.buffer.data(), (DWORD)w.buffer.size(), FALSE,
                FILE_NOTIFY_CHANGE_FILE_NAME, &bytes, &w.ov, nullptr)) {
            return true;
        }
        if (GetLastError() == ERROR_IO_PENDING) return true;
        m_health.RecordSourceError();
        return false;
    }

    void Drain(Watch& w, DWORD bytes) {
        size_t off = 0;
        while (off + sizeof(FILE_NOTIFY_INFORMATION) <= bytes) {
            auto* info = (const FILE_NOTIFY_INFORMATION*)(w.buffer.data() + off);
            const size_t filenameOffset = offsetof(FILE_NOTIFY_INFORMATION, FileName);
            if (info->FileNameLength % sizeof(WCHAR) != 0 ||
                info->FileNameLength > bytes - off - filenameOffset) {
                m_health.RecordParseError();
                return;
            }
            if (info->Action == FILE_ACTION_ADDED) {
                Event ev;
                ev.type = EDR_EVT_FILE_CREATE;
                ev.source = "directory_watch";
                ev.fields[field::kSource] = ev.source;
                FILETIME ft;
                GetSystemTimePreciseAsFileTime(&ft);
                ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) |
                             ft.dwLowDateTime;
                ev.fields[field::kType] = "FILE_CREATE";
                /* No pid/image available from RDCW (documented blind spot). */
                std::wstring full = Utf8ToWide(w.root);
                if (!full.empty() && full.back() != L'\\') {
                    full.push_back(L'\\');
                }
                full.append(info->FileName, info->FileNameLength / sizeof(WCHAR));
                ev.fields[field::kFilePath] = WideToUtf8(full.c_str());
                if (m_bus != nullptr) {
                    m_health.RecordEventSubmitted(!m_bus->Push(ev));
                }
            }
            if (info->NextEntryOffset == 0) {
                break;
            }
            if (info->NextEntryOffset < filenameOffset + info->FileNameLength ||
                info->NextEntryOffset > bytes - off) {
                m_health.RecordParseError();
                return;
            }
            off += info->NextEntryOffset;
        }
        if (off != bytes && off + sizeof(FILE_NOTIFY_INFORMATION) > bytes)
            m_health.RecordParseError();
    }

public:
    CollectorHealthSnapshot GetHealthSnapshot() const override {
        const bool unavailable = m_noActiveWatches.load();
        return m_health.Snapshot(unavailable ? "no_active_watches" : "stopped",
                                 m_activeWatches.load(), true,
                                 m_watchSetupComplete.load());
    }

private:
    std::vector<std::string> m_dirs;
    CollectorRuntimeHealth m_health;
    std::atomic<size_t> m_activeWatches{0};
    std::atomic<bool> m_noActiveWatches{false};
    std::atomic<bool> m_watchSetupComplete{false};
    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    HANDLE m_stopEvent = nullptr;
};

ICollector* CreateFileFallbackCollector(std::vector<std::string> dirs) {
    return new FileFallbackCollector(std::move(dirs));
}

} // namespace edr
