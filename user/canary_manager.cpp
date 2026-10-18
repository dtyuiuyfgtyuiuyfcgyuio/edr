/*
 * canary_manager.cpp - Canary (honeypot) file collector implementation.
 *
 * See canary_manager.h for the contract. Deployment writes a small decoy
 * document whenever the configured path does not exist yet; existing files
 * are adopted as-is so operators can plant their own bait.
 */
#include "canary_manager.h"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <utility>

#include "edr_event.h"
#include "event_bus.h"
#include "file_reputation.h"

namespace edr {

namespace {

const char* const kCanaryContent =
    "<!-- EDR canary file. This document is a decoy planted by the EDR "
    "agent. Any program or user that opens, modifies, renames, or deletes "
    "it triggers a high-confidence alert. Do not touch. -->\r\n"
    "Q3 salary adjustments - CONFIDENTIAL\r\n"
    "(canary content - no real data inside)\r\n";

std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) return std::wstring();
    int needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
                                     static_cast<int>(text.size()),
                                     nullptr, 0);
    if (needed <= 0) return std::wstring();
    std::wstring wide(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
                        static_cast<int>(text.size()), &wide[0], needed);
    return wide;
}

uint64_t FileTimeTo100ns(const FILETIME& ft) {
    return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

} // namespace

CanaryManager::CanaryManager(uint32_t pollMs, uint64_t maxFileBytes,
                             std::vector<std::string> files)
    : m_pollMs(pollMs ? pollMs : 30000), m_maxFileBytes(maxFileBytes),
      m_files(std::move(files)) {}

CanaryManager::~CanaryManager() { Stop(); }

bool CanaryManager::Start(EventBus* bus) {
    if (m_thread.joinable()) return true;
    if (bus == nullptr) return false;
    if (m_files.empty()) return false;
    m_bus = bus;
    m_stop.store(false);

    for (const std::string& path : m_files) {
        if (Deploy(path)) {
            m_deployed.push_back(path);
        } else {
            std::fprintf(stderr,
                "[edr-canary] cannot deploy %s (parent dir missing?)\n",
                path.c_str());
        }
    }
    if (m_deployed.empty()) {
        std::fprintf(stderr, "[edr-canary] no canaries deployed; disabled\n");
        m_bus = nullptr;
        return false;
    }

    try {
        m_thread = std::thread(&CanaryManager::Run, this);
    } catch (...) {
        m_stop.store(true);
        m_bus = nullptr;
        return false;
    }
    std::fprintf(stderr, "[edr-canary] watching %zu canary file(s)\n",
                 m_deployed.size());
    return true;
}

void CanaryManager::Stop() {
    m_stop.store(true);
    if (m_thread.joinable()) m_thread.join();
    m_bus = nullptr;
}

/* Creates the decoy file when absent. Returns true when the path exists
 * afterwards (either just created or pre-existing operator bait). */
bool CanaryManager::Deploy(const std::string& utf8Path) {
    std::wstring wide = Utf8ToWide(utf8Path);
    DWORD attributes = GetFileAttributesW(wide.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES &&
        !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        return true; /* pre-existing file: adopt as-is */
    }
    HANDLE handle = CreateFileW(wide.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        /* ERROR_FILE_EXISTS races are fine (adopted next snapshot). */
        return GetLastError() == ERROR_FILE_EXISTS;
    }
    DWORD written = 0;
    WriteFile(handle, kCanaryContent,
              static_cast<DWORD>(strlen(kCanaryContent)), &written, nullptr);
    CloseHandle(handle);
    return true;
}

CanaryManager::Snapshot CanaryManager::TakeSnapshot(
        const std::wstring& widePath) {
    Snapshot snapshot;
    WIN32_FILE_ATTRIBUTE_DATA data = {};
    if (!GetFileAttributesExW(widePath.c_str(), GetFileExInfoStandard,
                              &data)) {
        return snapshot; /* present=false */
    }
    snapshot.present = true;
    snapshot.size = (static_cast<uint64_t>(data.nFileSizeHigh) << 32) |
                    data.nFileSizeLow;
    snapshot.writeTime100ns = FileTimeTo100ns(data.ftLastWriteTime);
    snapshot.accessTime100ns = FileTimeTo100ns(data.ftLastAccessTime);
    if (snapshot.size <= m_maxFileBytes) {
        FileReputationSettings settings;
        settings.enabled = true;
        settings.maxFileBytes = m_maxFileBytes;
        settings.cacheOnlyTrust = true;
        FileReputationResult result = GetFileReputation(widePath, settings);
        if (result.status == FileReputationStatus::Complete)
            snapshot.sha256 = result.sha256;
    }
    return snapshot;
}

void CanaryManager::Emit(const std::string& path, const char* action) {
    Event ev;
    ev.type = EDR_EVT_FILE_INTEGRITY;
    ev.source = "canary";
    FILETIME ft = {};
    GetSystemTimePreciseAsFileTime(&ft);
    ev.ts100ns = FileTimeTo100ns(ft);
    ev.fields[field::kSource] = ev.source;
    ev.fields[field::kType] = "FILE_INTEGRITY";
    ev.fields[field::kFimAction] = action;
    ev.fields[field::kFimPath] = path;
    ev.fields[field::kCanaryFlag] = "true";
    if (m_bus != nullptr) m_bus->Push(ev);
}

void CanaryManager::Run() {
    using Snapshots = std::map<std::string, Snapshot>;
    Snapshots baseline;
    for (const std::string& path : m_deployed)
        baseline[path] = TakeSnapshot(Utf8ToWide(path));
    bool firstPass = true;

    while (!m_stop.load()) {
        for (const std::string& path : m_deployed) {
            if (m_stop.load()) break;
            Snapshot now = TakeSnapshot(Utf8ToWide(path));
            auto it = baseline.find(path);
            if (firstPass || it == baseline.end()) continue;
            const Snapshot& before = it->second;

            if (before.present && !now.present) {
                Emit(path, "removed");
            } else if (!before.present && now.present) {
                Emit(path, "modified"); /* recreated after deletion */
            } else if (before.present && now.present) {
                if (before.size != now.size ||
                    before.writeTime100ns != now.writeTime100ns ||
                    (!before.sha256.empty() && !now.sha256.empty() &&
                     before.sha256 != now.sha256)) {
                    Emit(path, "modified");
                } else if (now.accessTime100ns > before.accessTime100ns) {
                    /* Content untouched but something read the bait. */
                    Emit(path, "accessed");
                }
            }
            baseline[path] = now;
        }
        firstPass = false;
        for (uint32_t waited = 0;
             waited < m_pollMs && !m_stop.load(); waited += 100) {
            Sleep(100);
        }
    }
}

ICollector* CreateCanaryCollector(uint32_t pollMs, uint64_t maxFileBytes,
                                  std::vector<std::string> files) {
    return new CanaryManager(pollMs, maxFileBytes, std::move(files));
}

} // namespace edr
