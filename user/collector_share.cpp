/* SMB shares: bounded complete snapshots; failed reads retain the baseline. */
#include <windows.h>
#include <lmcons.h>
#include <lmerr.h>
#include <lmshare.h>
#include <lmapibuf.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <utility>

#include "collector_share.h"
#include "collector_runtime_health.h"
#include "config.h"

namespace edr {
namespace {
constexpr size_t kMaxPages = 256;
constexpr size_t kMaxShares = 16384;
constexpr size_t kMaxNameBytes = 1024;
constexpr size_t kMaxValueBytes = 4096;
constexpr size_t kMaxPayloadBytes = 4 * 1024 * 1024;
constexpr DWORD kPageBytes = 64 * 1024;

bool ValidString(const std::string& value, size_t limit) {
    return value.size() <= limit && value.find('\0') == std::string::npos &&
        (value.empty() || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            value.data(), static_cast<int>(value.size()), nullptr, 0) != 0);
}
bool AcceptEntry(const ShareCollectorEntry& entry, size_t& chargedBytes,
                 std::set<std::string>& names) {
    if (entry.name.empty() || !ValidString(entry.name, kMaxNameBytes) ||
        !ValidString(entry.path, kMaxValueBytes) ||
        !ValidString(entry.type, kMaxValueBytes) ||
        !ValidString(entry.remark, kMaxValueBytes) || names.size() >= kMaxShares)
        return false;
    const size_t bytes = 256 + 2 * entry.name.size() + entry.path.size() +
                         entry.type.size() + entry.remark.size();
    if (bytes > kMaxPayloadBytes - chargedBytes || !names.insert(entry.name).second)
        return false;
    chargedBytes += bytes;
    return true;
}
bool ValidSnapshot(const ShareCollectorSnapshot& snapshot) {
    if (!snapshot.complete || snapshot.shares.size() > kMaxShares) return false;
    size_t charged = 0;
    std::set<std::string> names;
    for (const auto& entry : snapshot.shares)
        if (!AcceptEntry(entry, charged, names)) return false;
    return true;
}
const char* ShareTypeName(DWORD type) {
    switch (type) {
    case STYPE_DISKTREE: return "disk";
    case STYPE_PRINTQ: return "print";
    case STYPE_DEVICE: return "device";
    case STYPE_IPC: return "ipc";
    case STYPE_SPECIAL: return "special";
    default: return "other";
    }
}
struct NetBuffer {
    LPBYTE data = nullptr;
    NetBuffer() = default;
    NetBuffer(const NetBuffer&) = delete;
    NetBuffer& operator=(const NetBuffer&) = delete;
    ~NetBuffer() { if (data) NetApiBufferFree(data); }
};
/* NetAPI owns the strings, but cap their traversal and encoded payload too. */
bool ReadString(const NetBuffer& buffer, DWORD bytes, const wchar_t* text,
                std::string& result, size_t byteLimit) {
    result.clear();
    if (!text) return true;
    const auto base = reinterpret_cast<uintptr_t>(buffer.data);
    const auto address = reinterpret_cast<uintptr_t>(text);
    if (address < base || address - base >= bytes || address % alignof(wchar_t))
        return false;
    const size_t available = (bytes - (address - base)) / sizeof(wchar_t);
    const size_t bound = std::min(available, byteLimit + 1);
    size_t chars = 0;
    while (chars < bound && text[chars] != L'\0') ++chars;
    if (chars == bound || chars > byteLimit) return false;
    if (chars != 0 && WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        text, static_cast<int>(chars), nullptr, 0, nullptr, nullptr) == 0)
        return false;
    result = WideToUtf8(text, chars);
    return (chars == 0 || !result.empty()) && result.size() <= byteLimit;
}
ShareCollectorPage ReadNativePage(uint32_t resume) {
    NetBuffer buffer;
    DWORD read = 0, total = 0, next = resume;
    const NET_API_STATUS status = NetShareEnum(nullptr, 502, &buffer.data,
        kPageBytes, &read, &total, &next);
    ShareCollectorPage page;
    page.status = status;
    page.resumeHandle = next;
    if (status != NERR_Success && status != ERROR_MORE_DATA) return page;
    DWORD bufferBytes = 0;
    if (read > kMaxShares || (read != 0 && (!buffer.data ||
        NetApiBufferSize(buffer.data, &bufferBytes) != NERR_Success ||
        read > bufferBytes / sizeof(SHARE_INFO_502)))) {
        page.status = ERROR_INVALID_DATA;
        return page;
    }
    auto* shares = reinterpret_cast<const SHARE_INFO_502*>(buffer.data);
    page.shares.reserve(read);
    size_t charged = 0;
    std::set<std::string> names;
    for (DWORD i = 0; i < read; ++i) {
        ShareCollectorEntry entry;
        if (!ReadString(buffer, bufferBytes, shares[i].shi502_netname, entry.name, kMaxNameBytes) ||
            !ReadString(buffer, bufferBytes, shares[i].shi502_path, entry.path, kMaxValueBytes) ||
            !ReadString(buffer, bufferBytes, shares[i].shi502_remark, entry.remark, kMaxValueBytes)) {
            page.status = ERROR_INVALID_DATA;
            page.shares.clear();
            return page;
        }
        entry.type = ShareTypeName(shares[i].shi502_type);
        if (!AcceptEntry(entry, charged, names)) {
            page.status = ERROR_INVALID_DATA;
            page.shares.clear();
            return page;
        }
        page.shares.push_back(std::move(entry));
    }
    return page;
}
} // namespace

ShareCollectorSnapshot ReadShareCollectorSnapshot(const ShareCollectorPageQuery& query) {
    if (!query) return {};
    ShareCollectorSnapshot snapshot;
    size_t charged = 0;
    uint32_t resume = 0;
    std::set<uint32_t> seenResumes{0};
    std::set<std::string> names;
    for (size_t pages = 0; pages < kMaxPages; ++pages) {
        ShareCollectorPage page = query(resume);
        if ((page.status != ERROR_SUCCESS && page.status != ERROR_MORE_DATA) ||
            page.shares.size() > kMaxShares - snapshot.shares.size()) return {};
        for (auto& entry : page.shares) {
            if (!AcceptEntry(entry, charged, names)) return {};
            snapshot.shares.push_back(std::move(entry));
        }
        if (page.status == ERROR_SUCCESS) {
            snapshot.complete = true;
            return snapshot;
        }
        if (page.shares.empty() || !seenResumes.insert(page.resumeHandle).second) return {};
        resume = page.resumeHandle;
    }
    return {};
}

class ShareCollector : public ICollector {
public:
    ShareCollector(uint32_t pollMs, ShareCollectorQuery query = {})
        : m_pollMs(std::max(1u, pollMs)), m_query(std::move(query)) {}
    ~ShareCollector() override { Stop(); }
    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) return !m_workerFailed.load();
        if (!bus) return false;
        m_bus = bus;
        m_stop.store(false);
        m_explicitStop.store(false);
        m_workerFailed.store(false);
        try { m_thread = std::thread(&ShareCollector::Run, this); }
        catch (...) {
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
        auto sample = m_health.Snapshot(!m_explicitStop.load() && m_workerFailed.load()
            ? "source_error" : "stopped");
        sample.counters["shares_retained"] = m_retained.load();
        return sample;
    }
private:
    void Emit(const ShareCollectorEntry& share, const char* action) {
        Event ev;
        ev.type = EDR_EVT_SHARE_CHANGE;
        ev.source = "share_monitor";
        FILETIME now = {};
        GetSystemTimePreciseAsFileTime(&now);
        ev.ts100ns = (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
        ev.fields[field::kSource] = ev.source;
        ev.fields[field::kType] = "SHARE_CHANGE";
        ev.fields[field::kShareAction] = action;
        ev.fields[field::kShareName] = share.name;
        if (!share.path.empty()) ev.fields[field::kSharePath] = share.path;
        if (!share.type.empty()) ev.fields[field::kShareType] = share.type;
        if (!share.remark.empty()) ev.fields[field::kShareRemark] = share.remark;
        if (m_bus) m_health.RecordEventSubmitted(!m_bus->Push(ev));
    }
    void Run() noexcept {
        m_health.WorkerStarted();
        m_retained.store(0);
        try {
            std::map<std::string, ShareCollectorEntry> previous;
            bool seeded = false;
            while (!m_stop.load()) {
                auto snapshot = m_query ? m_query() : ReadShareCollectorSnapshot(ReadNativePage);
                if (!ValidSnapshot(snapshot)) {
                    m_health.RecordSourceError();
                } else {
                    std::map<std::string, ShareCollectorEntry> current;
                    for (auto& entry : snapshot.shares) {
                        std::string name = entry.name;
                        current.emplace(std::move(name), std::move(entry));
                    }
                    if (seeded) {
                        for (const auto& kv : current) {
                            const auto it = previous.find(kv.first);
                            if (it == previous.end()) Emit(kv.second, "added");
                            else if (it->second.path != kv.second.path ||
                                     it->second.type != kv.second.type ||
                                     it->second.remark != kv.second.remark)
                                Emit(kv.second, "modified");
                        }
                        for (const auto& kv : previous)
                            if (current.count(kv.first) == 0) Emit(kv.second, "removed");
                    }
                    previous = std::move(current);
                    seeded = true;
                    m_retained.store(previous.size());
                    m_health.RecordSnapshotSuccess();
                }
                uint32_t remaining = m_pollMs;
                while (remaining != 0 && !m_stop.load()) {
                    const auto delay = std::min(remaining, 100u);
                    Sleep(delay);
                    remaining -= delay;
                }
            }
        } catch (...) {
            m_workerFailed.store(true);
            m_health.RecordSourceError();
        }
        m_health.WorkerStopped();
    }
    uint32_t m_pollMs;
    ShareCollectorQuery m_query;
    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false}, m_explicitStop{false}, m_workerFailed{false};
    std::atomic<uint64_t> m_retained{0};
    CollectorRuntimeHealth m_health;
};
ICollector* CreateShareCollector(uint32_t pollMs) { return new ShareCollector(pollMs); }
ICollector* CreateShareCollector(uint32_t pollMs, ShareCollectorQuery query) {
    return new ShareCollector(pollMs, std::move(query));
}
} // namespace edr
