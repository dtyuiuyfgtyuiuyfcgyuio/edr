/*
 * collector_net_etw.cpp - ETW network-connection collector.
 *
 * Subscribes to Microsoft-Windows-Kernel-Network (GUID 7dd42a49-...) and
 * parses the fixed-offset payload of the IPv4/IPv6 connect/accept and UDP
 * send/receive templates by event ID (the payload `size` field is the packet
 * size and must never be used to discriminate v4 from v6). Emits NET_CONNECT
 * events with remote-interest filtering, mirroring the fallback collector's
 * skip-empty/loopback policy.
 */
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <evntrace.h>
#include <evntcons.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "collector.h"
#include "etw_health.h"
#include "config.h"
#include "edr_event.h"
#include "event_bus.h"
#include "collector_net_etw.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

namespace edr {

static const GUID kNetProvider = {
    0x7DD42A49, 0x5329, 0x4832,
    {0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88}
};

bool IsNetEtwKeepEvent(uint16_t eventId, bool udpEnabled) {
    switch (eventId) {
        case 12: /* TCPv4 connect */
        case 15: /* TCPv4 accept */
        case 28: /* TCPv6 connect */
        case 31: /* TCPv6 accept */
            return true;
        case 42: /* UDPv4 send */
        case 43: /* UDPv4 receive */
        case 58: /* UDPv6 send */
        case 59: /* UDPv6 receive */
            return udpEnabled;
        default:
            return false;
    }
}

bool ParseNetConnectPayload(uint16_t eventId, const uint8_t* payload,
                            uint32_t byteCount, NetConnectInfo& out) {
    uint32_t minLen = 0;
    bool ipv6 = false;
    bool udp = false;
    switch (eventId) {
        case 12: /* TCPv4 connect */
        case 15: /* TCPv4 accept */
            minLen = 44;
            break;
        case 42: /* UDPv4 send */
        case 43: /* UDPv4 receive */
            minLen = 28;
            udp = true;
            break;
        case 28: /* TCPv6 connect */
        case 31: /* TCPv6 accept */
            minLen = 68;
            ipv6 = true;
            break;
        case 58: /* UDPv6 send */
        case 59: /* UDPv6 receive */
            minLen = 52;
            ipv6 = true;
            udp = true;
            break;
        default:
            return false;
    }
    if (payload == nullptr || byteCount < minLen) {
        return false;
    }

    std::memset(&out, 0, sizeof(out));
    std::memcpy(&out.pid, payload, sizeof(out.pid)); /* host byte order */
    out.ipv6 = ipv6;
    out.udp = udp;
    if (ipv6) {
        std::memcpy(out.daddr, payload + 8, 16);
        std::memcpy(out.saddr, payload + 24, 16);
        std::memcpy(&out.dport, payload + 40, sizeof(out.dport));
        std::memcpy(&out.sport, payload + 42, sizeof(out.sport));
    } else {
        std::memcpy(&out.daddr[0], payload + 8, 4);
        std::memcpy(&out.saddr[0], payload + 12, 4);
        std::memcpy(&out.dport, payload + 16, sizeof(out.dport));
        std::memcpy(&out.sport, payload + 18, sizeof(out.sport));
    }
    return true;
}

std::string NetIpToString(bool ipv6, const uint32_t addr[4]) {
    char buf[INET6_ADDRSTRLEN];
    if (ipv6) {
        IN6_ADDR in6;
        /* addr is a little-endian array of 4 u32; copy the 16 raw bytes
         * sequentially so the wire order reaches InetNtopA unchanged. */
        std::memcpy(&in6, addr, sizeof(in6));
        if (InetNtopA(AF_INET6, &in6, buf, sizeof(buf)) == nullptr) {
            return std::string();
        }
        return std::string(buf);
    }
    uint32_t host = ntohl(addr[0]);
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  (host >> 24) & 0xFF, (host >> 16) & 0xFF,
                  (host >> 8) & 0xFF, host & 0xFF);
    return std::string(buf);
}

class NetEtwCollector : public ICollector {
public:
    explicit NetEtwCollector(bool udpEnabled)
        : m_udpEnabled(udpEnabled),
          m_sessionName(L"EDR-NetTrace-" + std::to_wstring(GetCurrentProcessId())) {}
    ~NetEtwCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) return true;
        m_bus = bus;
        m_stop.store(false);

        if (!StartEtwSession()) {
            std::fprintf(stderr,
                         "[edr-net] ETW unavailable; no longer attempting "
                         "NET events\n");
            return false;
        }

        try { m_thread = std::thread(&NetEtwCollector::Run, this); }
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
    static constexpr uint64_t kImageCacheMs = 10000;  /* lifespan, 10 s */
    static constexpr size_t kImageCacheMax = 2048;    /* entry cap */

    struct ImageCacheEntry {
        std::string image;
        uint64_t storedMs;
    };

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
            std::fprintf(stderr, "[edr-net] ControlTraceW stop failed: %lu\n", status);
        m_sessionHandle = 0;
    }

    static VOID WINAPI EventRecordCallback(EVENT_RECORD* rec) {
        auto* self = (NetEtwCollector*)rec->UserContext;
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
            std::fprintf(stderr, "[edr-net] StartTraceW failed: %lu\n", status);
            return false;
        }

        ENABLE_TRACE_PARAMETERS etp = {};
        etp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        etp.EnableProperty = 0;
        /* keyword 0x30 = IPv4 | IPv6 network events */
        status = EnableTraceEx2(m_sessionHandle, &kNetProvider,
                                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_INFORMATION, 0x30, 0, INFINITE, &etp);
        if (status != ERROR_SUCCESS) {
            std::fprintf(stderr, "[edr-net] EnableTraceEx2 failed: %lu\n", status);
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
            std::fprintf(stderr, "[edr-net] OpenTraceW failed: %lu\n", GetLastError());
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
        if (rec->EventHeader.ProviderId != kNetProvider) return;

        uint16_t id = rec->EventHeader.EventDescriptor.Id;
        if (!IsNetEtwKeepEvent(id, m_udpEnabled)) return;

        NetConnectInfo info;
        if (!ParseNetConnectPayload(id, (const uint8_t*)rec->UserData,
                                    rec->UserDataLength, info)) {
            return;
        }

        if (info.ipv6) {
            static const uint8_t kLoopback[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                                  0, 0, 0, 0, 0, 0, 0, 1};
            if (std::memcmp(info.daddr, kLoopback, 16) == 0) return;
            if ((info.daddr[0] | info.daddr[1] | info.daddr[2] | info.daddr[3]) == 0)
                return;
        } else {
            uint32_t host = ntohl(info.daddr[0]);
            if (host == 0) return;
            if ((host >> 24) == 127) return; /* loopback */
        }

        Event ev;
        ev.type = EDR_EVT_NET_CONNECT;
        ev.ts100ns = static_cast<uint64_t>(rec->EventHeader.TimeStamp.QuadPart);
        ev.pid = info.pid;
        ev.source = "net_etw";
        ev.fields[field::kSource] = ev.source;
        ev.fields[field::kType] = "NET_CONNECT";
        ev.fields[field::kPid] = std::to_string(info.pid);
        ev.fields[field::kDstIp] = NetIpToString(info.ipv6, info.daddr);
        ev.fields[field::kDstPort] = std::to_string(ntohs(info.dport));
        ev.fields[field::kSrcIp] = NetIpToString(info.ipv6, info.saddr);
        ev.fields[field::kSrcPort] = std::to_string(ntohs(info.sport));
        ev.fields[field::kProtocol] = info.udp ? "udp" : "tcp";
        std::string image = ResolveImage(info.pid);
        if (!image.empty()) ev.fields[field::kImage] = image;
        if (m_bus != nullptr) m_bus->Push(ev);
    }

    static std::string ImageForPid(uint32_t pid) {
        if (pid == 0) {
            return std::string();
        }
        HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (p == nullptr) {
            return std::string();
        }
        wchar_t path[MAX_PATH];
        DWORD size = (DWORD)std::size(path);
        std::string out;
        if (QueryFullProcessImageNameW(p, 0, path, &size)) {
            out = WideToUtf8(path, size);
        }
        CloseHandle(p);
        return out;
    }

    std::string ResolveImage(uint32_t pid) {
        uint64_t nowMs = GetTickCount64();
        auto it = m_imageCache.find(pid);
        if (it != m_imageCache.end()) {
            if (nowMs - it->second.storedMs <= kImageCacheMs) {
                return it->second.image; /* cached hit, including misses */
            }
            m_imageCache.erase(it); /* expired */
        }
        std::string image = ImageForPid(pid);
        if (m_imageCache.size() >= kImageCacheMax) {
            m_imageCache.clear();
        }
        m_imageCache[pid] = ImageCacheEntry{image, nowMs};
        return image;
    }

    EventBus* m_bus = nullptr;
    bool m_udpEnabled;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_workerActive{false};
    TRACEHANDLE m_sessionHandle = 0;
    TRACEHANDLE m_traceHandle = 0;
    std::wstring m_sessionName;
    std::unordered_map<uint32_t, ImageCacheEntry> m_imageCache;
};

ICollector* CreateNetEtwCollector(bool udpEnabled) {
    return new NetEtwCollector(udpEnabled);
}

} // namespace edr
