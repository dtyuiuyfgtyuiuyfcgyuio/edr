#include <windows.h>
#include <tlhelp32.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include "collector.h"
#include "collector_runtime_health.h"
#include "config.h"
#include "edr_event.h"
#include "event_bus.h"
#include "process_query.h"

namespace edr {

static uint64_t ProcessCreateTime(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return 0;
    FILETIME create = {}, exit = {}, kernel = {}, user = {};
    bool ok = GetProcessTimes(process, &create, &exit, &kernel, &user) != FALSE;
    CloseHandle(process);
    return ok ? ((static_cast<uint64_t>(create.dwHighDateTime) << 32) |
                 create.dwLowDateTime) : 0;
}

/* Cache of PID -> full image path so a process visible across multiple poll
 * cycles only pays QueryFullProcessImageNameW once (until it exits). */
class PollImagePathCache {
public:
    explicit PollImagePathCache(size_t maxSize = 512) : m_maxSize(maxSize) {}

    std::string Get(DWORD pid) {
        auto it = m_cache.find(pid);
        if (it != m_cache.end()) return it->second;
        std::string path = ResolveProcessImagePath(pid);
        if (!path.empty()) {
            if (m_cache.size() >= m_maxSize) m_cache.erase(m_cache.begin());
            m_cache[pid] = path;
        }
        return path;
    }

    void Erase(DWORD pid) { m_cache.erase(pid); }

private:
    size_t m_maxSize;
    std::unordered_map<DWORD, std::string> m_cache;
};

class ProcPollCollector : public ICollector {
public:
    explicit ProcPollCollector(bool fullImage = true) : m_fullImage(fullImage) {}
    ~ProcPollCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) return true;
        m_bus = bus;
        m_stop.store(false);
        try { m_thread = std::thread(&ProcPollCollector::Run, this); }
        catch (...) { m_health.RecordSourceError(); return false; }
        return true;
    }

    void Stop() override {
        m_stop.store(true);
        if (m_thread.joinable()) m_thread.join();
    }

private:
    void Run() {
        m_health.WorkerStarted();
        struct ActivityGuard {
            CollectorRuntimeHealth& health;
            ~ActivityGuard() { health.WorkerStopped(); }
        } activity{m_health};
        std::unordered_set<DWORD> known;
        bool firstPass = true;

        while (!m_stop.load()) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE) {
                m_health.RecordSourceError();
                Sleep(500);
                continue;
            }
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (!Process32FirstW(snap, &pe)) {
                const DWORD error = GetLastError();
                if (error != ERROR_NO_MORE_FILES) m_health.RecordSourceError();
                CloseHandle(snap);
                Sleep(500);
                continue;
            }
            bool complete = true;
            for (;;) {
                if (known.find(pe.th32ProcessID) == known.end()) {
                    known.insert(pe.th32ProcessID);
                    if (!firstPass) {
                        FILETIME ft;
                        GetSystemTimePreciseAsFileTime(&ft);
                        Event ev;
                        ev.type = EDR_EVT_PROCESS_START;
                        ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
                        ev.pid = pe.th32ProcessID;
                        ev.ppid = pe.th32ParentProcessID;
                        ev.processStartTime100ns = ProcessCreateTime(ev.pid);
                        if (ev.processStartTime100ns != 0)
                            ev.processIdentity = std::to_string(ev.pid) + "@" +
                                std::to_string(ev.processStartTime100ns);
                        ev.source = "process_poll";
                        ev.fields[field::kSource] = ev.source;
                        ev.fields["type"] = "PROCESS_START";
                        const std::string basename = WideToUtf8(pe.szExeFile);
                        ev.fields["image"] = basename;
                        if (m_fullImage) {
                            const std::string fullPath =
                                m_pathCache.Get(pe.th32ProcessID);
                            if (!fullPath.empty())
                                ev.fields[field::kImagePath] = fullPath;
                        }
                        ev.fields["pid"] = std::to_string(pe.th32ProcessID);
                        ev.fields["ppid"] = std::to_string(pe.th32ParentProcessID);
                        std::string cmdline =
                            ReadProcessCommandLine(pe.th32ProcessID);
                        if (!cmdline.empty()) {
                            ev.fields["command_line"] = cmdline;
                        }
                        if (m_bus)
                            m_health.RecordEventSubmitted(!m_bus->Push(ev));
                    }
                }
                if (m_stop.load()) {
                    complete = false;
                    break;
                }
                SetLastError(ERROR_SUCCESS);
                if (!Process32NextW(snap, &pe)) {
                    const DWORD error = GetLastError();
                    if (error != ERROR_NO_MORE_FILES) {
                        m_health.RecordSourceError();
                        complete = false;
                    }
                    break;
                }
            }
            CloseHandle(snap);
            if (!complete) {
                for (int i = 0; i < 8 && !m_stop.load(); i++) Sleep(250 / 8);
                continue;
            }
            m_health.RecordSnapshotSuccess();
            firstPass = false;

            for (auto it = known.begin(); it != known.end(); ) {
                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, *it);
                if (h == NULL) {
                    const DWORD error = GetLastError();
                    if (error == ERROR_INVALID_PARAMETER) {
                        m_pathCache.Erase(*it);
                        it = known.erase(it);
                    } else if (error == ERROR_ACCESS_DENIED) {
                        ++it; /* protected processes are an expected blind spot */
                    } else {
                        m_health.RecordSourceError();
                        ++it;
                    }
                } else {
                    CloseHandle(h);
                    ++it;
                }
            }

            for (int i = 0; i < 8 && !m_stop.load(); i++) Sleep(250 / 8);
        }
    }

    EventBus* m_bus = nullptr;
    CollectorRuntimeHealth m_health;
    bool m_fullImage = true;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    PollImagePathCache m_pathCache;

public:
    CollectorHealthSnapshot GetHealthSnapshot() const override {
        return m_health.Snapshot();
    }
};

ICollector* CreateProcPollCollector(bool fullImage) {
    return new ProcPollCollector(fullImage);
}

} // namespace edr
