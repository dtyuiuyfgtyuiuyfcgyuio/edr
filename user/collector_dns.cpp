#include <windows.h>
#include <tdh.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "collector.h"
#include "etw_health.h"
#include "dns_etw_parser.h"
#include "config.h"
#include "edr_event.h"
#include "event_bus.h"
#include "process_query.h"

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "dnsapi.lib")

namespace edr {

/* Microsoft-Windows-DNS-Client ETW Provider GUID */
static const GUID kDnsProvider = {
    0x1C95126E, 0x7EEA, 0x49A9,
    {0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D}
};

/* DNS Event IDs from Microsoft-Windows-DNS-Client */
enum DnsEventId {
    DNS_EVENT_QUERY = 3008,    /* DNS query completed */
    DNS_EVENT_STARTED = 3009, /* DNS network query initiated */
};

class DnsEtwCollector : public ICollector {
public:
    DnsEtwCollector()
        : m_sessionName(L"EDR-DnsTrace-" + std::to_wstring(GetCurrentProcessId())) {}
    ~DnsEtwCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) return true;
        m_bus = bus;
        m_stop.store(false);

        if (!StartEtwSession()) {
            std::fprintf(stderr, "[edr-dns] ETW unavailable; DNS events disabled\n");
            return false;
        }

        try { m_thread = std::thread(&DnsEtwCollector::Run, this); }
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
            std::fprintf(stderr, "[edr-dns] ControlTraceW stop failed: %lu\n", status);
        m_sessionHandle = 0;
    }

    static VOID WINAPI EventRecordCallback(EVENT_RECORD* rec) {
        auto* self = (DnsEtwCollector*)rec->UserContext;
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
            std::fprintf(stderr, "[edr-dns] StartTraceW failed: %lu\n", status);
            return false;
        }

        ENABLE_TRACE_PARAMETERS etp = {};
        etp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        etp.EnableProperty = EVENT_ENABLE_PROPERTY_SID;
        status = EnableTraceEx2(m_sessionHandle, &kDnsProvider,
                                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFFULL, 0,
                                INFINITE, &etp);
        if (status != ERROR_SUCCESS) {
            std::fprintf(stderr, "[edr-dns] EnableTraceEx2 failed: %lu\n", status);
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
            std::fprintf(stderr, "[edr-dns] OpenTraceW failed: %lu\n", GetLastError());
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
        if (rec->EventHeader.ProviderId != kDnsProvider) return;

        const auto& header = rec->EventHeader;
        Event event;
        const DnsPropertyReader read = [this, rec](const wchar_t* name,
                                                   std::vector<uint8_t>& bytes) {
            return GetPropertyData(rec, name, bytes);
        };
        if (!ParseDnsEtwEvent(header.EventDescriptor.Id,
                header.EventDescriptor.Version, header.ProcessId,
                static_cast<uint64_t>(header.TimeStamp.QuadPart), read, event)) return;
        std::string image;
        uint64_t startTime = 0;
        if (ResolveProcessContext(event.pid, event.ts100ns, image, startTime)) {
            event.fields[field::kImage] = std::move(image);
            event.processStartTime100ns = startTime;
        }
        m_bus->Push(event);
    }

    DnsPropertyStatus GetPropertyData(EVENT_RECORD* record, const wchar_t* name,
                                      std::vector<uint8_t>& bytes) {
        PROPERTY_DATA_DESCRIPTOR descriptor = {};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
        descriptor.ArrayIndex = 0;
        ULONG size = 0;
        const ULONG status = TdhGetPropertySize(record, 0, nullptr, 1,
                                                &descriptor, &size);
        if (status == ERROR_NOT_FOUND) return DnsPropertyStatus::Missing;
        if (status != ERROR_SUCCESS || size == 0 || size > kDnsMaxPropertyBytes)
            return DnsPropertyStatus::Invalid;
        bytes.resize(size);
        return TdhGetProperty(record, 0, nullptr, 1, &descriptor, size,
                              bytes.data()) == ERROR_SUCCESS
            ? DnsPropertyStatus::Present : DnsPropertyStatus::Invalid;
    }

    EventBus* m_bus = nullptr;
    TRACEHANDLE m_sessionHandle = 0;
    TRACEHANDLE m_traceHandle = 0;
    std::wstring m_sessionName;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_workerActive{false};
};

ICollector* CreateDnsEtwCollector() {
    return new DnsEtwCollector();
}

} // namespace edr
