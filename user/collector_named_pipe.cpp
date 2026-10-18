/*
 * collector_named_pipe.cpp - ETW named pipe monitoring collector.
 *
 * Subscribes to Microsoft-Windows-Kernel-File (GUID edd08927-9cc4-4e65-b970-c2560fb5c289)
 * and parses pipe create (event ID 17) and pipe connect (event ID 18) events.
 * Emits NAMED_PIPE events with pipe name and operation type.
 *
 * The ETW payload layout for pipe events (Windows 10+):
 *   - Event ID 17 (PipeCreated): [PID(4)][TID(4)][CreateTime(8)][PipeName(<=512)]
 *   - Event ID 18 (PipeConnected): [PID(4)][TID(4)][PipeName(<=512)]
 * PipeName is a null-terminated UTF-16LE string.
 */
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "collector.h"
#include "etw_health.h"
#include "config.h"
#include "edr_event.h"
#include "event_bus.h"
#include "collector_named_pipe.h"

#pragma comment(lib, "advapi32.lib")

namespace edr {

/* Microsoft-Windows-Kernel-File provider GUID */
static const GUID kFileProvider = {
    0xEDD08927, 0x9CC4, 0x4E65,
    {0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}
};

/* ETW event IDs for named pipe operations */
static const uint16_t kEventPipeCreated = 17;
static const uint16_t kEventPipeConnected = 18;

/* Minimum payload: PID(4) + TID(4) + at least 2 bytes of pipe name */
static const uint32_t kMinPipePayload = 10;

std::string ParsePipeName(const uint8_t* payload, uint32_t byteCount) {
    if (payload == nullptr || byteCount < kMinPipePayload) {
        return std::string();
    }
    /* Pipe name starts at offset 8 (after PID + TID). */
    uint32_t nameOffset = 8;
    if (byteCount <= nameOffset) {
        return std::string();
    }
    uint32_t nameBytes = byteCount - nameOffset;
    /* Round down to even (UTF-16). */
    nameBytes &= ~1u;
    if (nameBytes < 2) {
        return std::string();
    }
    /* Strip trailing nulls. */
    while (nameBytes >= 2 &&
           reinterpret_cast<const wchar_t*>(payload + nameOffset)[(nameBytes / 2) - 1] == L'\0') {
        nameBytes -= 2;
    }
    if (nameBytes == 0) {
        return std::string();
    }
    size_t units = nameBytes / 2;
    const wchar_t* wide = reinterpret_cast<const wchar_t*>(payload + nameOffset);
    /* Strip the \Device\NamedPipe\ prefix for cleaner output. */
    static const wchar_t kPrefix[] = L"\\Device\\NamedPipe\\";
    static const size_t kPrefixLen = (sizeof(kPrefix) / sizeof(wchar_t)) - 1;
    const wchar_t* displayName = wide;
    size_t displayUnits = units;
    if (units >= kPrefixLen &&
        _wcsnicmp(wide, kPrefix, kPrefixLen) == 0) {
        displayName = wide + kPrefixLen;
        displayUnits = units - kPrefixLen;
    }
    return WideToUtf8(displayName, displayUnits);
}

class NamedPipeCollector : public ICollector {
public:
    NamedPipeCollector()
        : m_sessionName(L"EDR-PipeTrace-" +
                        std::to_wstring(GetCurrentProcessId())) {}
    ~NamedPipeCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) return true;
        m_bus = bus;
        m_stop.store(false);

        if (!StartEtwSession()) {
            std::fprintf(stderr,
                "[edr-pipe] ETW unavailable; named pipe monitoring disabled\n");
            return false;
        }

        try {
            m_thread = std::thread(&NamedPipeCollector::Run, this);
        } catch (...) {
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
        if (m_thread.joinable()) {
            m_thread.join();
        }
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
        wcscpy(reinterpret_cast<wchar_t*>(
            buffer.data() + properties->LoggerNameOffset),
            m_sessionName.c_str());
        ULONG status = ControlTraceW(m_sessionHandle, m_sessionName.c_str(),
            properties, EVENT_TRACE_CONTROL_STOP);
        if (status != ERROR_SUCCESS &&
            status != ERROR_WMI_INSTANCE_NOT_FOUND) {
            std::fprintf(stderr,
                "[edr-pipe] ControlTraceW stop failed: %lu\n", status);
        }
        m_sessionHandle = 0;
    }

    static VOID WINAPI EventRecordCallback(EVENT_RECORD* rec) {
        auto* self = reinterpret_cast<NamedPipeCollector*>(rec->UserContext);
        if (self && !self->m_stop.load()) {
            self->OnEventRecord(rec);
        }
    }

    bool StartEtwSession() {
        ULONG bufSize = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) +
            (m_sessionName.size() + 1) * sizeof(wchar_t));
        std::vector<uint8_t> buf(bufSize);
        auto* prop = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data());
        prop->Wnode.BufferSize = bufSize;
        prop->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        prop->Wnode.ClientContext = 2; /* system time (FILETIME epoch) */
        prop->BufferSize = 256;
        prop->MinimumBuffers = 2;
        prop->MaximumBuffers = 16;
        prop->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        wcscpy(reinterpret_cast<wchar_t*>(
            reinterpret_cast<char*>(prop) + prop->LoggerNameOffset),
            m_sessionName.c_str());

        ULONG status = StartTraceW(&m_sessionHandle,
            m_sessionName.c_str(), prop);
        if (status != ERROR_SUCCESS) {
            std::fprintf(stderr,
                "[edr-pipe] StartTraceW failed: %lu\n", status);
            return false;
        }

        /* Keyword 0x10 = pipe events (create/connect). */
        ENABLE_TRACE_PARAMETERS etp = {};
        etp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        etp.EnableProperty = 0;
        status = EnableTraceEx2(m_sessionHandle, &kFileProvider,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION, 0x10, 0, INFINITE, &etp);
        if (status != ERROR_SUCCESS) {
            std::fprintf(stderr,
                "[edr-pipe] EnableTraceEx2 failed: %lu\n", status);
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
            std::fprintf(stderr,
                "[edr-pipe] OpenTraceW failed: %lu\n", GetLastError());
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
        if (rec->EventHeader.ProviderId != kFileProvider) return;

        uint16_t id = rec->EventHeader.EventDescriptor.Id;
        if (id != kEventPipeCreated && id != kEventPipeConnected) return;

        const uint8_t* payload =
            static_cast<const uint8_t*>(rec->UserData);
        uint32_t byteCount = rec->UserDataLength;

        if (payload == nullptr || byteCount < kMinPipePayload) return;

        std::string pipeName = ParsePipeName(payload, byteCount);
        if (pipeName.empty()) return;

        /* Extract PID from payload offset 0. */
        uint32_t pid = 0;
        std::memcpy(&pid, payload, sizeof(pid));

        Event ev;
        ev.type = EDR_EVT_NAMED_PIPE;
        ev.ts100ns = static_cast<uint64_t>(
            rec->EventHeader.TimeStamp.QuadPart);
        ev.pid = pid;
        ev.source = "named_pipe_etw";
        ev.fields[field::kSource] = ev.source;
        ev.fields[field::kType] = "NAMED_PIPE";
        ev.fields[field::kPid] = std::to_string(pid);
        ev.fields[field::kPipeName] = pipeName;
        ev.fields[field::kPipeOperation] =
            (id == kEventPipeCreated) ? "created" : "connected";

        if (m_bus != nullptr) m_bus->Push(ev);
    }

    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_workerActive{false};
    TRACEHANDLE m_sessionHandle = 0;
    TRACEHANDLE m_traceHandle = 0;
    std::wstring m_sessionName;
};

ICollector* CreateNamedPipeCollector() {
    return new NamedPipeCollector();
}

} // namespace edr
