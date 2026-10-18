#include <windows.h>

#include <atomic>
#include <algorithm>
#include <cstdio>
#include <cwctype>
#include <map>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "collector.h"
#include "collector_startup_watch.h"
#include "config.h"
#include "edr_event.h"

namespace edr {

namespace {

bool IsServiceProfilePath(const std::wstring& path) {
    std::wstring folded = path;
    for (wchar_t& ch : folded) ch = static_cast<wchar_t>(towlower(ch));
    return folded.find(L"\\windows\\serviceprofiles\\") != std::wstring::npos ||
        folded.find(L"\\windows\\system32\\config\\systemprofile") !=
            std::wstring::npos;
}

} // namespace

std::vector<StartupDirectory> CanonicalStartupDirectories(
        const std::vector<StartupDirectory>& directories, bool requireExisting) {
    std::vector<StartupDirectory> result;
    std::vector<std::wstring> seen;
    for (const auto& directory : directories) {
        wchar_t full[32768];
        DWORD length = GetFullPathNameW(directory.first.c_str(),
            static_cast<DWORD>(std::size(full)), full, nullptr);
        if (!length || length >= std::size(full)) continue;
        std::wstring canonical(full, length);
        DWORD attributes = GetFileAttributesW(canonical.c_str());
        if (requireExisting && (attributes == INVALID_FILE_ATTRIBUTES ||
                               !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
                               (attributes & FILE_ATTRIBUTE_REPARSE_POINT)))
            continue;
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            DWORD needed = GetLongPathNameW(canonical.c_str(), nullptr, 0);
            if (needed) {
                /* GetLongPathNameW may fail for an otherwise valid path
                 * (for example on filesystems without long-name metadata).
                 * Keep the GetFileAttributesW-validated path in that case. */
                std::wstring expanded(static_cast<size_t>(needed) + 1,
                                      L'\0');
                DWORD expandedLength = GetLongPathNameW(
                    canonical.c_str(), expanded.data(),
                    static_cast<DWORD>(expanded.size()));
                if (expandedLength &&
                    expandedLength < expanded.size()) {
                    expanded.resize(expandedLength);
                    canonical = std::move(expanded);
                }
            }
        }
        while (canonical.size() > 3 && canonical.back() == L'\\')
            canonical.pop_back();
        std::wstring folded = canonical;
        for (wchar_t& ch : folded) ch = static_cast<wchar_t>(towlower(ch));
        if (std::find(seen.begin(), seen.end(), folded) != seen.end()) continue;
        seen.push_back(std::move(folded));
        result.push_back({std::move(canonical), directory.second});
    }
    return result;
}

std::vector<StartupDirectory> DiscoverProfileStartupDirectories(HKEY profileList) {
    std::vector<StartupDirectory> candidates;
    DWORD maxSubKey = 0;
    if (RegQueryInfoKeyW(profileList, nullptr, nullptr, nullptr, nullptr,
            &maxSubKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) !=
            ERROR_SUCCESS) return candidates;
    std::vector<wchar_t> sid(static_cast<size_t>(maxSubKey) + 2);
    const std::wstring suffix = L"\\AppData\\Roaming\\Microsoft\\Windows" \
        L"\\Start Menu\\Programs\\Startup";
    for (DWORD i = 0;; ++i) {
        DWORD sidLength = static_cast<DWORD>(sid.size());
        LONG rc = RegEnumKeyExW(profileList, i, sid.data(), &sidLength,
                                nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) continue;
        std::wstring sidValue(sid.data(), sidLength);
        if (sidValue == L"S-1-5-18" || sidValue == L"S-1-5-19" ||
            sidValue == L"S-1-5-20") continue;
        HKEY profile = nullptr;
        if (RegOpenKeyExW(profileList, sidValue.c_str(), 0, KEY_QUERY_VALUE,
                          &profile) != ERROR_SUCCESS) continue;
        DWORD type = 0, bytes = 0;
        rc = RegQueryValueExW(profile, L"ProfileImagePath", nullptr, &type,
                              nullptr, &bytes);
        if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) ||
            bytes < sizeof(wchar_t) || bytes > 32768 * sizeof(wchar_t)) {
            RegCloseKey(profile); continue;
        }
        std::vector<wchar_t> value(bytes / sizeof(wchar_t) + 1, L'\0');
        rc = RegQueryValueExW(profile, L"ProfileImagePath", nullptr, &type,
                              reinterpret_cast<BYTE*>(value.data()), &bytes);
        RegCloseKey(profile);
        if (rc != ERROR_SUCCESS) continue;
        std::wstring profilePath(value.data());
        if (type == REG_EXPAND_SZ) {
            DWORD needed = ExpandEnvironmentStringsW(profilePath.c_str(), nullptr, 0);
            if (!needed) continue;
            std::wstring expanded(needed, L'\0');
            DWORD length = ExpandEnvironmentStringsW(profilePath.c_str(),
                                                       expanded.data(), needed);
            if (!length || length > needed) continue;
            expanded.resize(length - 1);
            profilePath = std::move(expanded);
        }
        if (IsServiceProfilePath(profilePath)) continue;
        candidates.push_back({profilePath + suffix, false});
    }
    return CanonicalStartupDirectories(candidates, true);
}

std::vector<StartupDirectory> DiscoverFallbackStartupDirectories(HKEY profileList) {
    std::wstring root = L"C:\\Users";
    if (profileList != nullptr) {
        DWORD type = 0, bytes = 0;
        LONG rc = RegQueryValueExW(profileList, L"ProfilesDirectory", nullptr,
                                   &type, nullptr, &bytes);
        if (rc == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ) &&
            bytes >= sizeof(wchar_t) && bytes <= 32768 * sizeof(wchar_t)) {
            std::vector<wchar_t> value(bytes / sizeof(wchar_t) + 1, L'\0');
            rc = RegQueryValueExW(profileList, L"ProfilesDirectory", nullptr,
                                  &type, reinterpret_cast<BYTE*>(value.data()),
                                  &bytes);
            if (rc == ERROR_SUCCESS) {
                DWORD needed = ExpandEnvironmentStringsW(value.data(), nullptr, 0);
                if (needed) {
                    std::wstring expanded(needed, L'\0');
                    DWORD length = ExpandEnvironmentStringsW(
                        value.data(), expanded.data(), needed);
                    if (length && length <= needed) {
                        expanded.resize(length - 1);
                        root = std::move(expanded);
                    }
                }
            }
        }
    }
    while (root.size() > 3 && root.back() == L'\\') root.pop_back();

    std::vector<StartupDirectory> candidates;
    const std::wstring suffix = L"\\AppData\\Roaming\\Microsoft\\Windows" \
        L"\\Start Menu\\Programs\\Startup";
    WIN32_FIND_DATAW data = {};
    HANDLE find = FindFirstFileW((root + L"\\*").c_str(), &data);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                wcscmp(data.cFileName, L".") == 0 ||
                wcscmp(data.cFileName, L"..") == 0) continue;
            std::wstring profilePath = root + L"\\" + data.cFileName;
            if (IsServiceProfilePath(profilePath)) continue;
            candidates.push_back({profilePath + suffix, false});
        } while (FindNextFileW(find, &data));
        FindClose(find);
    }
    return CanonicalStartupDirectories(candidates, true);
}

namespace {

struct FileState {
    uint64_t size = 0;
    uint64_t lastWrite = 0;
};

using Snapshot = std::map<std::wstring, FileState>;

/* Scope for explicitly configured dirs: per-user startup folders live under
 * AppData\Roaming; anything else is treated as a machine-wide location. */
bool IsUserScopePath(const std::wstring& path) {
    std::wstring lower = path;
    for (wchar_t& ch : lower) ch = static_cast<wchar_t>(towlower(ch));
    return lower.find(L"\\appdata\\roaming\\") != std::wstring::npos;
}

Snapshot TakeSnapshot(const std::wstring& dir) {
    Snapshot snapshot;
    std::wstring pattern = dir + L"\\*";
    WIN32_FIND_DATAW data = {};
    HANDLE find = FindFirstFileW(pattern.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return snapshot;
    do {
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        FileState state;
        state.size = (static_cast<uint64_t>(data.nFileSizeHigh) << 32) |
                     data.nFileSizeLow;
        state.lastWrite =
            (static_cast<uint64_t>(data.ftLastWriteTime.dwHighDateTime) << 32) |
            data.ftLastWriteTime.dwLowDateTime;
        snapshot[data.cFileName] = state;
    } while (FindNextFileW(find, &data));
    FindClose(find);
    return snapshot;
}

bool ArmDir(HANDLE dirHandle, std::vector<BYTE>& buffer,
            OVERLAPPED& overlapped) {
    ResetEvent(overlapped.hEvent);
    DWORD bytes = 0;
    if (ReadDirectoryChangesW(dirHandle, buffer.data(),
            static_cast<DWORD>(buffer.size()), FALSE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE |
                FILE_NOTIFY_CHANGE_SIZE,
            &bytes, &overlapped, nullptr)) {
        return true; /* completed synchronously */
    }
    return GetLastError() == ERROR_IO_PENDING;
}

} // namespace

class StartupWatchCollector : public ICollector {
public:
    explicit StartupWatchCollector(std::vector<std::string> dirs)
        : m_configDirs(std::move(dirs)) {}

    ~StartupWatchCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (!m_watches.empty()) return true;
        if (bus == nullptr) return false;
        m_bus = bus;
        m_stop.store(false);

        m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (m_stopEvent == nullptr) {
            m_bus = nullptr;
            return false;
        }

        std::vector<StartupDirectory> dirs;
        if (!m_configDirs.empty()) {
            for (const std::string& dir : m_configDirs) {
                std::wstring wide = Utf8ToWide(dir);
                if (wide.empty()) continue;
                dirs.push_back({wide, !IsUserScopePath(wide)});
            }
            dirs = CanonicalStartupDirectories(dirs, false);
        } else {
            /* Defaults: the all-users Startup folder plus one per profile.
             * An elevated agent's own %APPDATA% resolves to the service
             * profile, so real user folders are enumerated. */
            dirs.push_back({Utf8ToWide(ExpandEnvStrings(
                "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")),
                true});
            HKEY profileList = nullptr;
            std::vector<StartupDirectory> profiles;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
                    0, KEY_READ, &profileList) == ERROR_SUCCESS) {
                profiles = DiscoverProfileStartupDirectories(profileList);
                auto fallback = DiscoverFallbackStartupDirectories(profileList);
                profiles.insert(profiles.end(), fallback.begin(), fallback.end());
                RegCloseKey(profileList);
            } else {
                profiles = DiscoverFallbackStartupDirectories(nullptr);
            }
            dirs.insert(dirs.end(), profiles.begin(), profiles.end());
            dirs = CanonicalStartupDirectories(dirs, true);
        }

        /* ReadDirectoryChangesW retains the OVERLAPPED address until the
         * request is drained. Reserve final capacity and construct each
         * Watch in place before arming it so that address never changes. */
        m_watches.reserve(dirs.size());
        for (const auto& dir : dirs) {
            DWORD attributes = GetFileAttributesW(dir.first.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES ||
                !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
                std::fprintf(stderr, "[edr-startup-watch] skipping missing dir %s\n",
                             WideToUtf8(dir.first.c_str()).c_str());
                continue;
            }
            m_watches.emplace_back();
            Watch& watch = m_watches.back();
            watch.path = dir.first;
            watch.machine = dir.second;
            /* Arm + baseline synchronously so changes after Start() returns
             * are guaranteed to be observed. */
            if (!OpenWatch(watch)) {
                std::fprintf(stderr, "[edr-startup-watch] cannot watch %s: %lu\n",
                             WideToUtf8(dir.first.c_str()).c_str(), GetLastError());
                m_errors.fetch_add(1);
                m_watches.pop_back();
                continue;
            }
        }

        bool threadStartFailed = false;
        for (Watch& watch : m_watches) {
            try {
                m_threads.emplace_back(&StartupWatchCollector::WatchLoop,
                                       this, &watch);
            } catch (...) {
                std::fprintf(stderr, "[edr-startup-watch] thread start failed\n");
                m_errors.fetch_add(1);
                threadStartFailed = true;
                break;
            }
        }
        if (threadStartFailed || m_threads.empty()) {
            if (!threadStartFailed) {
                std::fprintf(stderr,
                    "[edr-startup-watch] no startup folders watched\n");
            }
            Stop();
            return false;
        }
        return true;
    }

    void Stop() override {
        m_stop.store(true);
        if (m_stopEvent != nullptr) SetEvent(m_stopEvent);
        for (auto& thread : m_threads) {
            if (thread.joinable()) thread.join();
        }
        m_threads.clear();
        for (Watch& watch : m_watches) CloseWatch(watch);
        m_watches.clear();
        if (m_stopEvent != nullptr) {
            CloseHandle(m_stopEvent);
            m_stopEvent = nullptr;
        }
        m_bus = nullptr;
        std::fprintf(stderr,
            "[edr-startup-watch] overflows=%llu errors=%llu\n",
            static_cast<unsigned long long>(m_overflows.load()),
            static_cast<unsigned long long>(m_errors.load()));
    }

private:
    struct Watch {
        std::wstring path;
        bool machine = false;
        HANDLE dirHandle = nullptr;
        HANDLE ioEvent = nullptr;
        std::vector<BYTE> buffer;
        OVERLAPPED overlapped = {};
        Snapshot baseline;
        bool armed = false; /* an overlapped request is outstanding */
    };

    static bool OpenWatch(Watch& watch) {
        watch.dirHandle = CreateFileW(watch.path.c_str(), FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
        if (watch.dirHandle == INVALID_HANDLE_VALUE) {
            watch.dirHandle = nullptr;
            return false;
        }
        watch.ioEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (watch.ioEvent == nullptr) {
            CloseHandle(watch.dirHandle);
            watch.dirHandle = nullptr;
            return false;
        }
        watch.buffer.assign(4096, 0);
        watch.overlapped = {};
        watch.overlapped.hEvent = watch.ioEvent;
        /* Arm before the baseline so changes after arming are not missed. */
        if (!ArmDir(watch.dirHandle, watch.buffer, watch.overlapped)) {
            CloseHandle(watch.ioEvent);
            CloseHandle(watch.dirHandle);
            watch.ioEvent = nullptr;
            watch.dirHandle = nullptr;
            return false;
        }
        watch.armed = true;
        watch.baseline = TakeSnapshot(watch.path);
        return true;
    }

    /* Cancel + drain any outstanding request so the kernel cannot write
     * into overlapped/buffer after the Watch is destroyed. */
    static void DrainWatch(Watch& watch) {
        if (!watch.armed) return;
        CancelIoEx(watch.dirHandle, &watch.overlapped);
        DWORD bytes = 0;
        GetOverlappedResult(watch.dirHandle, &watch.overlapped, &bytes, TRUE);
        watch.armed = false;
    }

    static void CloseWatch(Watch& watch) {
        if (watch.dirHandle != nullptr) {
            DrainWatch(watch);
            CloseHandle(watch.dirHandle);
            watch.dirHandle = nullptr;
        }
        if (watch.ioEvent != nullptr) {
            CloseHandle(watch.ioEvent);
            watch.ioEvent = nullptr;
        }
    }

    void EmitDiff(const Watch& watch, const Snapshot& baseline,
                  const Snapshot& current) {
        auto emit = [&](const std::wstring& name, uint16_t type,
                        const char* action) {
            Event ev;
            ev.type = type;
            ev.source = "startup_folder_watch";
            ev.fields[field::kSource] = ev.source;
            ev.fields[field::kType] = EventTypeName(ev.type);
            std::wstring full = watch.path + L"\\" + name;
            ev.fields[field::kFilePath] = WideToUtf8(full.c_str());
            ev.fields[field::kFileAction] = action;
            ev.fields[field::kStartupScope] = watch.machine ? "machine" : "user";
            FILETIME ft = {};
            GetSystemTimePreciseAsFileTime(&ft);
            ev.ts100ns = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) |
                         ft.dwLowDateTime;
            EventBus* bus = m_bus;
            if (bus != nullptr) bus->Push(ev);
        };

        for (const auto& kv : current) {
            auto it = baseline.find(kv.first);
            const char* action = nullptr;
            if (it == baseline.end()) {
                action = "added";
            } else if (it->second.size != kv.second.size ||
                       it->second.lastWrite != kv.second.lastWrite) {
                action = "modified";
            } else {
                continue;
            }
            emit(kv.first, EDR_EVT_FILE_CREATE, action);
        }
        for (const auto& kv : baseline) {
            if (current.find(kv.first) == current.end()) {
                emit(kv.first, EDR_EVT_FILE_DELETE, "deleted");
            }
        }
    }

    void WatchLoop(Watch* watch) {
        HANDLE waitHandles[2] = {m_stopEvent, watch->ioEvent};
        while (!m_stop.load()) {
            DWORD wait = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0) break;
            if (wait != WAIT_OBJECT_0 + 1) {
                if (wait == WAIT_FAILED) m_errors.fetch_add(1);
                continue;
            }
            DWORD bytes = 0;
            BOOL ok = GetOverlappedResult(watch->dirHandle, &watch->overlapped,
                                          &bytes, FALSE);
            DWORD error = ok ? ERROR_SUCCESS : GetLastError();
            if (!ok && error == ERROR_IO_INCOMPLETE) {
                m_errors.fetch_add(1);
                std::fprintf(stderr,
                    "[edr-startup-watch] signaled request still pending\n");
                break;
            }
            watch->armed = false;
            if (error == ERROR_NOTIFY_ENUM_DIR) {
                m_overflows.fetch_add(1);
            } else if (!ok) {
                if (m_stop.load()) break;
                m_errors.fetch_add(1);
                std::fprintf(stderr,
                    "[edr-startup-watch] GetOverlappedResult failed: %lu\n",
                    error);
            }
            /* Re-arm before re-snapshotting so no change falls between the
             * notification and the next snapshot; any notification (or an
             * overflow) triggers a full re-snapshot and diff. */
            watch->overlapped = {};
            watch->overlapped.hEvent = watch->ioEvent;
            if (!ArmDir(watch->dirHandle, watch->buffer, watch->overlapped)) {
                m_errors.fetch_add(1);
                std::fprintf(stderr,
                    "[edr-startup-watch] re-arm failed: %lu\n", GetLastError());
                break;
            }
            watch->armed = true;
            Snapshot current = TakeSnapshot(watch->path);
            EmitDiff(*watch, watch->baseline, current);
            watch->baseline = std::move(current);
        }
        DrainWatch(*watch);
    }

    EventBus* m_bus = nullptr;
    std::vector<std::string> m_configDirs;
    std::vector<Watch> m_watches;
    std::vector<std::thread> m_threads;
    HANDLE m_stopEvent = nullptr;
    std::atomic<bool> m_stop{false};
    std::atomic<uint64_t> m_overflows{0};
    std::atomic<uint64_t> m_errors{0};
};

ICollector* CreateStartupWatchCollector(std::vector<std::string> dirs) {
    return new StartupWatchCollector(std::move(dirs));
}

} // namespace edr
