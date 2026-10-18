#include <windows.h>
#include <tdh.h>
#include <sddl.h>
#include <atomic>
#include <cstdio>
#include <initializer_list>
#include <map>
#include <string>
#include <thread>
#include <vector>
#include "collector.h"
#include "etw_health.h"
#include "config.h"
#include "edr_event.h"
#include "event_bus.h"
#include "process_query.h"

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

namespace edr {

static const GUID kProcProvider = {
    0x22FB2CD6, 0x0E7B, 0x422B,
    {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}
};

/* Small LRU-style cache for PID->full image path to avoid repeated
 * QueryFullProcessImageNameW calls on the same PID within a short window. */
class ProcImagePathCache {
public:
    explicit ProcImagePathCache(size_t maxSize = 256) : m_maxSize(maxSize) {}

    std::string Get(DWORD pid) {
        auto it = m_cache.find(pid);
        if (it != m_cache.end()) return it->second;
        std::string path = ResolveProcessImagePath(pid);
        if (!path.empty()) {
            if (m_cache.size() >= m_maxSize) {
                m_cache.erase(m_cache.begin());
            }
            m_cache[pid] = path;
        }
        return path;
    }

    void Erase(DWORD pid) { m_cache.erase(pid); }

private:
    size_t m_maxSize;
    std::map<DWORD, std::string> m_cache;
};

class ProcEtwCollector : public ICollector {
public:
    explicit ProcEtwCollector(bool fullImage = true, bool userSid = false)
        : m_fullImage(fullImage), m_userSid(userSid),
          m_sessionName(L"EDR-Proctrace-" + std::to_wstring(GetCurrentProcessId())) {}
    ~ProcEtwCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) return true;
        m_bus = bus;
        m_stop.store(false);

        if (!StartEtwSession()) {
            std::fprintf(stderr, "[edr-etw] ETW unavailable; proc events disabled\n");
            return false;
        }

        try { m_thread = std::thread(&ProcEtwCollector::Run, this); }
        catch (...) {
            CloseTrace(m_traceHandle);
            m_traceHandle = 0;
            StopEtwSession();
            return false;
        }
        return true;
    }

    void Stop() override {
        m_stop.store(true);
        StopEtwSession();
        if (m_traceHandle && m_traceHandle != INVALID_PROCESSTRACE_HANDLE) {
            CloseTrace(m_traceHandle);
            m_traceHandle = 0;
        }
        if (m_thread.joinable()) m_thread.join();
    }

    CollectorHealthSnapshot GetHealthSnapshot() const override {
        return SampleEtwSessionHealth(m_sessionName, m_workerActive.load());
    }

private:
    void StopEtwSession() {
        if (!m_sessionHandle) return;
        ULONG size = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) +
            (m_sessionName.size() + 1) * sizeof(wchar_t));
        std::vector<uint8_t> buffer(size);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
        properties->Wnode.BufferSize = size;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        wcscpy(reinterpret_cast<wchar_t*>(buffer.data() + properties->LoggerNameOffset),
               m_sessionName.c_str());
        ULONG status = ControlTraceW(m_sessionHandle, m_sessionName.c_str(), properties,
                                     EVENT_TRACE_CONTROL_STOP);
        if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND)
            std::fprintf(stderr, "[edr-etw] ControlTraceW stop failed: %lu\n", status);
        m_sessionHandle = 0;
    }

    static VOID WINAPI EventRecordCallback(EVENT_RECORD* rec) {
        auto* self = (ProcEtwCollector*)rec->UserContext;
        if (self && !self->m_stop.load()) self->OnEventRecord(rec);
    }

    bool StartEtwSession() {
        ULONG bufSize = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) +
            (m_sessionName.size() + 1) * sizeof(wchar_t));
        std::vector<uint8_t> buf(bufSize);
        auto* prop = (EVENT_TRACE_PROPERTIES*)buf.data();
        prop->Wnode.BufferSize = bufSize;
        prop->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        prop->Wnode.ClientContext = 2; // system time (FILETIME epoch)
        prop->BufferSize = 256;
        prop->MinimumBuffers = 2;
        prop->MaximumBuffers = 16;
        prop->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        wcscpy((wchar_t*)((char*)prop + prop->LoggerNameOffset), m_sessionName.c_str());

        ULONG status = StartTraceW(&m_sessionHandle, m_sessionName.c_str(), prop);
        if (status != ERROR_SUCCESS) {
            std::fprintf(stderr, "[edr-etw] StartTraceW failed: %lu\n", status);
            return false;
        }

        ENABLE_TRACE_PARAMETERS etp = {};
        etp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        etp.EnableProperty = EVENT_ENABLE_PROPERTY_SID;
        status = EnableTraceEx2(m_sessionHandle, &kProcProvider,
                                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_INFORMATION, 0x10, 0, INFINITE, &etp);
        if (status != ERROR_SUCCESS) {
            std::fprintf(stderr, "[edr-etw] EnableTraceEx2 failed: %lu\n", status);
            StopEtwSession();
            return false;
        }

        EVENT_TRACE_LOGFILEW logfile = {};
        logfile.LoggerName = const_cast<LPWSTR>(m_sessionName.c_str());
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                                   PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.EventRecordCallback = EventRecordCallback;
        logfile.Context = this;
        m_traceHandle = OpenTraceW(&logfile);
        if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
            std::fprintf(stderr, "[edr-etw] OpenTraceW failed: %lu\n", GetLastError());
            m_traceHandle = 0;
            StopEtwSession();
            return false;
        }

        return true;
    }

    void Run() {
        m_workerActive.store(true);
        ProcessTrace(&m_traceHandle, 1, nullptr, nullptr);
        m_workerActive.store(false);
    }

    void OnEventRecord(EVENT_RECORD* rec) {
        if (rec->EventHeader.ProviderId != kProcProvider) return;

        if (rec->EventHeader.EventDescriptor.Id == 1) {
            OnProcessStart(rec);
        } else if (rec->EventHeader.EventDescriptor.Id == 2) {
            OnProcessStop(rec);
        }
    }

    static bool PropertyBytes(EVENT_RECORD* rec, const wchar_t* name,
                              std::vector<uint8_t>& value) {
        PROPERTY_DATA_DESCRIPTOR descriptor = {};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
        descriptor.ArrayIndex = ULONG_MAX;
        ULONG size = 0;
        ULONG status = TdhGetPropertySize(rec, 0, nullptr, 1, &descriptor, &size);
        if (status != ERROR_SUCCESS || size == 0 || size > 64 * 1024) return false;
        value.resize(size);
        status = TdhGetProperty(rec, 0, nullptr, 1, &descriptor, size, value.data());
        return status == ERROR_SUCCESS;
    }

    static bool UInt32Property(EVENT_RECORD* rec,
                               std::initializer_list<const wchar_t*> names,
                               DWORD& value) {
        std::vector<uint8_t> bytes;
        for (const wchar_t* name : names) {
            if (PropertyBytes(rec, name, bytes) && bytes.size() >= sizeof(value)) {
                memcpy(&value, bytes.data(), sizeof(value));
                return true;
            }
        }
        return false;
    }

    static bool UInt64Property(EVENT_RECORD* rec,
                               std::initializer_list<const wchar_t*> names,
                               uint64_t& value) {
        std::vector<uint8_t> bytes;
        for (const wchar_t* name : names) {
            if (PropertyBytes(rec, name, bytes) && bytes.size() >= sizeof(value)) {
                memcpy(&value, bytes.data(), sizeof(value));
                return true;
            }
        }
        return false;
    }

    static std::string StringProperty(EVENT_RECORD* rec,
                                      std::initializer_list<const wchar_t*> names) {
        std::vector<uint8_t> bytes;
        for (const wchar_t* name : names) {
            if (!PropertyBytes(rec, name, bytes)) continue;
            if (bytes.size() >= sizeof(wchar_t) && bytes.size() % sizeof(wchar_t) == 0) {
                const wchar_t* value = reinterpret_cast<const wchar_t*>(bytes.data());
                size_t count = bytes.size() / sizeof(wchar_t);
                size_t length = 0;
                while (length < count && value[length] != L'\0') ++length;
                if (length != 0) return WideToUtf8(std::wstring(value, length).c_str());
            }
            const char* value = reinterpret_cast<const char*>(bytes.data());
            size_t length = 0;
            while (length < bytes.size() && value[length] != '\0') ++length;
            if (length != 0) return std::string(value, length);
        }
        return {};
    }

    /* Extract UserSID from the event and convert to string form.
     * Tries the TDH property "UserSID" first, then falls back to the
     * event header SID (set via EVENT_ENABLE_PROPERTY_SID). */
    static std::string ExtractUserSid(EVENT_RECORD* rec) {
        /* Try TDH property first. */
        std::vector<uint8_t> bytes;
        if (PropertyBytes(rec, L"UserSID", bytes) && bytes.size() >= sizeof(SID)) {
            PSID sid = reinterpret_cast<PSID>(bytes.data());
            if (IsValidSid(sid)) {
                wchar_t* sidStr = nullptr;
                if (ConvertSidToStringSidW(sid, &sidStr) && sidStr) {
                    std::string result = WideToUtf8(sidStr);
                    LocalFree(sidStr);
                    return result;
                }
            }
        }
        /* Fall back to the SID extended-data item (populated via
         * EVENT_ENABLE_PROPERTY_SID); EVENT_HEADER carries no UserSid
         * member, the payload lives in ExtendedData. */
        for (ULONG i = 0; i < rec->ExtendedDataCount; ++i) {
            const EVENT_HEADER_EXTENDED_DATA_ITEM& item =
                rec->ExtendedData[i];
            if (item.ExtType != EVENT_HEADER_EXT_TYPE_SID ||
                item.DataPtr == 0 || item.DataSize < sizeof(SID))
                continue;
            PSID sid = reinterpret_cast<PSID>(item.DataPtr);
            if (!IsValidSid(sid)) continue;
            wchar_t* sidStr = nullptr;
            if (ConvertSidToStringSidW(sid, &sidStr) && sidStr) {
                std::string result = WideToUtf8(sidStr);
                LocalFree(sidStr);
                return result;
            }
        }
        return {};
    }

    void OnProcessStart(EVENT_RECORD* rec) {
        DWORD pid = 0, ppid = 0;
        if (!UInt32Property(rec, {L"ProcessID", L"ProcessId"}, pid) || pid == 0) return;
        UInt32Property(rec, {L"ParentProcessID", L"ParentProcessId"}, ppid);
        uint64_t createTime = 0;
        UInt64Property(rec, {L"CreateTime"}, createTime);
        uint64_t processSequence = 0, parentSequence = 0;
        UInt64Property(rec, {L"ProcessSequenceNumber"}, processSequence);
        UInt64Property(rec, {L"ParentProcessSequenceNumber"}, parentSequence);
        std::string image = StringProperty(rec, {L"ImageName", L"Image"});
        std::string cmdline = StringProperty(rec, {L"CommandLine"});
        if (cmdline.empty()) cmdline = ReadProcessCommandLine(pid);

        /* Resolve full image path if enabled. */
        std::string imagePath;
        if (m_fullImage) {
            imagePath = m_pathCache.Get(pid);
            if (imagePath.empty()) {
                /* Fallback: try to construct from basename + System32. */
                if (!image.empty())
                    imagePath = "C:\\Windows\\System32\\" + image;
            }
        }
        /* Cache the full path for parent resolution. */
        ProcessInfo processInfo{image, imagePath, createTime, processSequence};
        m_pidCache[pid] = processInfo;

        /* Resolve parent image — prefer full path, fall back to basename. */
        std::string parentImage;
        std::string evParentIdentity;
        auto it = m_pidCache.find(ppid);
        if (it != m_pidCache.end()) {
            parentImage = !it->second.imagePath.empty()
                ? it->second.imagePath : it->second.image;
            if (it->second.createTime != 0)
                evParentIdentity = std::to_string(ppid) + "@" +
                                   std::to_string(it->second.createTime);
        }

        /* Session ID */
        DWORD sessionId = 0;
        UInt32Property(rec, {L"SessionID"}, sessionId);

        Event ev;
        ev.type = EDR_EVT_PROCESS_START;
        ev.ts100ns = static_cast<uint64_t>(rec->EventHeader.TimeStamp.QuadPart);
        ev.pid = pid;
        ev.ppid = ppid;
        ev.processStartTime100ns = createTime;
        if (processSequence != 0)
            ev.processIdentity = "sequence@" + std::to_string(processSequence);
        else if (createTime != 0)
            ev.processIdentity = std::to_string(pid) + "@" + std::to_string(createTime);
        ev.parentProcessIdentity = parentSequence != 0
            ? "sequence@" + std::to_string(parentSequence) : evParentIdentity;
        ev.source = "etw";
        ev.fields[field::kSource] = ev.source;
        ev.fields["type"] = "PROCESS_START";
        ev.fields["image"] = image;
        if (!imagePath.empty()) ev.fields[field::kImagePath] = imagePath;
        if (!parentImage.empty()) ev.fields["parent_image"] = parentImage;
        if (sessionId != 0) ev.fields[field::kSessionId] = std::to_string(sessionId);
        ev.fields["pid"] = std::to_string(pid);
        ev.fields["ppid"] = std::to_string(ppid);
        if (!cmdline.empty()) ev.fields["command_line"] = cmdline;

        /* User SID (opt-in). */
        if (m_userSid) {
            std::string sid = ExtractUserSid(rec);
            if (!sid.empty()) ev.fields[field::kUserSid] = sid;
        }

        if (m_bus) m_bus->Push(ev);
    }

    void OnProcessStop(EVENT_RECORD* rec) {
        DWORD pid = 0;
        if (!UInt32Property(rec, {L"ProcessID", L"ProcessId"}, pid) || pid == 0) return;

        /* Extract exit status from the stop event. */
        DWORD exitStatus = 0;
        UInt32Property(rec, {L"ExitStatus"}, exitStatus);

        ProcessInfo processInfo;
        auto found = m_pidCache.find(pid);
        if (found != m_pidCache.end()) processInfo = found->second;
        m_pidCache.erase(pid);
        m_pathCache.Erase(pid);

        Event ev;
        ev.type = EDR_EVT_PROCESS_STOP;
        ev.ts100ns = static_cast<uint64_t>(rec->EventHeader.TimeStamp.QuadPart);
        ev.pid = pid;
        ev.processStartTime100ns = processInfo.createTime;
        if (processInfo.sequence != 0)
            ev.processIdentity = "sequence@" + std::to_string(processInfo.sequence);
        else if (processInfo.createTime != 0)
            ev.processIdentity = std::to_string(pid) + "@" +
                                 std::to_string(processInfo.createTime);
        ev.source = "etw";
        ev.fields[field::kSource] = ev.source;
        ev.fields["type"] = "PROCESS_STOP";
        ev.fields["pid"] = std::to_string(pid);
        if (!processInfo.image.empty()) ev.fields["image"] = processInfo.image;
        if (!processInfo.imagePath.empty())
            ev.fields[field::kImagePath] = processInfo.imagePath;
        if (exitStatus != 0) ev.fields[field::kExitStatus] = std::to_string(exitStatus);
        if (m_bus) m_bus->Push(ev);
    }

    EventBus* m_bus = nullptr;
    struct ProcessInfo {
        std::string image;
        std::string imagePath;
        uint64_t createTime = 0;
        uint64_t sequence = 0;
    };
    bool m_fullImage = true;
    bool m_userSid = false;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_workerActive{false};
    TRACEHANDLE m_sessionHandle = 0;
    TRACEHANDLE m_traceHandle = 0;
    std::map<DWORD, ProcessInfo> m_pidCache;
    ProcImagePathCache m_pathCache;
    std::wstring m_sessionName;
};

ICollector* CreateProcEtwCollector(bool fullImage, bool userSid) {
    return new ProcEtwCollector(fullImage, userSid);
}

} // namespace edr
