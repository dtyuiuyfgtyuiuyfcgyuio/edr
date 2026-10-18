/*
 * collector_net_fallback.cpp - TCP table polling NET_CONNECT source.
 *
 * Every pollMs (default 5s) snapshots GetExtendedTcpTable and diffs against
 * the previous snapshot; new outbound endpoints are correlated PID -> image
 * name and emitted as
 * NET_CONNECT events. Blind spot (documented in README): connections
 * shorter than one poll interval are missed.
 */
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <atomic>
#include <cstddef>
#include <cstdio>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "collector.h"
#include "collector_runtime_health.h"
#include "config.h"
#include "edr_event.h"

namespace edr {

class NetFallbackCollector : public ICollector {
public:
    explicit NetFallbackCollector(uint32_t pollMs) : m_pollMs(pollMs) {}
    ~NetFallbackCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) {
            return true;
        }
        m_bus = bus;
        m_stop.store(false);
        try {
            m_thread = std::thread(&NetFallbackCollector::Run, this);
        } catch (...) {
            m_health.RecordSourceError();
            m_stop.store(true);
            m_bus = nullptr;
            return false;
        }
        return true;
    }

    void Stop() override {
        m_stop.store(true);
        if (m_thread.joinable()) {
            m_thread.join();
        }
    }

private:
    struct Endpoint {
        uint32_t remoteIp; /* network byte order as returned by the API */
        uint16_t remotePort;
        uint32_t pid;
        bool udp;

        bool operator<(const Endpoint& o) const {
            if (remoteIp != o.remoteIp) return remoteIp < o.remoteIp;
            if (remotePort != o.remotePort) return remotePort < o.remotePort;
            if (pid != o.pid) return pid < o.pid;
            return udp < o.udp;
        }
    };

    static bool IsInterestingRemote(uint32_t networkOrderIp) {
        /* Skip empty/loopback remote endpoints. */
        uint32_t host = ntohl(networkOrderIp);
        if (host == 0) {
            return false;
        }
        if ((host >> 24) == 127) {
            return false;
        }
        return true;
    }

    static std::string IpToString(uint32_t networkOrderIp) {
        uint32_t host = ntohl(networkOrderIp);
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                      (host >> 24) & 0xFF, (host >> 16) & 0xFF,
                      (host >> 8) & 0xFF, host & 0xFF);
        return buf;
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

    bool Snapshot(std::set<Endpoint>& result) {
        result.clear();
        constexpr DWORD kMaxTableBytes = 32u * 1024u * 1024u;
        std::vector<uint8_t> buffer;
        DWORD size = 0;
        DWORD status = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                                           TCP_TABLE_OWNER_PID_ALL, 0);
        if (status == NO_ERROR && size == 0) {
            m_health.RecordSnapshotSuccess();
            return true;
        }
        if (status != ERROR_INSUFFICIENT_BUFFER || size == 0 ||
            size > kMaxTableBytes) {
            m_health.RecordSourceError();
            return false;
        }

        bool fetched = false;
        for (unsigned attempt = 0; attempt < 3; ++attempt) {
            buffer.resize(size);
            DWORD available = size;
            status = GetExtendedTcpTable(buffer.data(), &available, FALSE,
                                         AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (status == NO_ERROR) {
                size = available;
                fetched = true;
                break;
            }
            if (status != ERROR_INSUFFICIENT_BUFFER || available == 0 ||
                available > kMaxTableBytes || attempt == 2) {
                m_health.RecordSourceError();
                return false;
            }
            size = available;
        }
        if (!fetched || size < sizeof(DWORD)) {
            m_health.RecordSourceError();
            return false;
        }

        const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(
            buffer.data());
        const size_t maxRows = (size - offsetof(MIB_TCPTABLE_OWNER_PID, table)) /
                               sizeof(MIB_TCPROW_OWNER_PID);
        if (table->dwNumEntries > maxRows) {
            m_health.RecordParseError();
            return false;
        }
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            const MIB_TCPROW_OWNER_PID& row = table->table[i];
            if (row.dwState != MIB_TCP_STATE_ESTAB &&
                row.dwState != MIB_TCP_STATE_SYN_SENT) {
                continue;
            }
            if (!IsInterestingRemote(row.dwRemoteAddr)) continue;
            Endpoint ep;
            ep.remoteIp = row.dwRemoteAddr;
            ep.remotePort = ntohs((u_short)row.dwRemotePort);
            ep.pid = row.dwOwningPid;
            ep.udp = false;
            result.insert(ep);
        }
        m_health.RecordSnapshotSuccess();
        return true;
    }

    void Run() {
        m_health.WorkerStarted();
        struct ActivityGuard {
            CollectorRuntimeHealth& health;
            ~ActivityGuard() { health.WorkerStopped(); }
        } activity{m_health};
        std::set<Endpoint> previous;
        bool haveBaseline = Snapshot(previous); /* baseline: no burst */
        while (!m_stop.load()) {
            for (uint32_t t = 0; t < m_pollMs && !m_stop.load(); t += 100) {
                Sleep(100);
            }
            if (m_stop.load()) {
                break;
            }
            std::set<Endpoint> current;
            if (!Snapshot(current)) continue;
            if (!haveBaseline) {
                previous = std::move(current);
                haveBaseline = true;
                continue;
            }
            for (const Endpoint& ep : current) {
                if (previous.count(ep) != 0) {
                    continue;
                }
                Event ev;
                ev.type = EDR_EVT_NET_CONNECT;
                ev.pid = ep.pid;
                ev.source = "network_poll";
                ev.fields[field::kSource] = ev.source;
                FILETIME ft;
                GetSystemTimePreciseAsFileTime(&ft);
                ev.ts100ns = ((uint64_t)ft.dwHighDateTime << 32) |
                             ft.dwLowDateTime;
                ev.fields[field::kType] = "NET_CONNECT";
                ev.fields[field::kPid] = std::to_string(ep.pid);
                ev.fields[field::kDstIp] = IpToString(ep.remoteIp);
                ev.fields[field::kDstPort] = std::to_string(ep.remotePort);
                std::string image = ImageForPid(ep.pid);
                if (!image.empty()) {
                    ev.fields[field::kImage] = image;
                }
                if (m_bus != nullptr) {
                    m_health.RecordEventSubmitted(!m_bus->Push(ev));
                }
            }
            previous = std::move(current);
        }
    }

    uint32_t m_pollMs;
    CollectorRuntimeHealth m_health;
    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};

public:
    CollectorHealthSnapshot GetHealthSnapshot() const override {
        return m_health.Snapshot();
    }
};

ICollector* CreateNetFallbackCollector(uint32_t pollMs) {
    return new NetFallbackCollector(pollMs);
}

} // namespace edr
