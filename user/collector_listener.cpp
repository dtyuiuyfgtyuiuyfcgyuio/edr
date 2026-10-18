/* Independent complete TCP4/UDP4/TCP6/UDP6 snapshots. A failed domain never
 * advances its baseline; first success seeds it without an event burst. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>
#include "collector.h"
#include "collector_listener.h"
#include "collector_runtime_health.h"
#include "edr_event.h"
#include "process_query.h"

namespace edr {
namespace {
constexpr ListenerTableDomain kDomains[] = {ListenerTableDomain::Tcp4,
    ListenerTableDomain::Udp4, ListenerTableDomain::Tcp6, ListenerTableDomain::Udp6};
constexpr const char* kDomainNames[] = {"tcp4", "udp4", "tcp6", "udp6"};
bool IsV6(ListenerTableDomain domain) {
    return domain == ListenerTableDomain::Tcp6 || domain == ListenerTableDomain::Udp6;
}
bool IsUdp(ListenerTableDomain domain) {
    return domain == ListenerTableDomain::Udp4 || domain == ListenerTableDomain::Udp6;
}
uint64_t Now100ns() {
    FILETIME now{};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
}
bool ValidImage(const std::string& image) {
    if (image.size() > kListenerMaxImageBytes || image.find('\0') != std::string::npos)
        return false;
    return image.empty() || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        image.data(), static_cast<int>(image.size()), nullptr, 0) > 0;
}
bool Charge(size_t& used, size_t bytes) {
    if (bytes > kListenerRetainedMaxBytes - used) return false;
    used += bytes;
    return true;
}
uint32_t NativeRead(ListenerTableDomain domain, void* buffer, uint32_t* bytes) {
    DWORD size = *bytes;
    const ULONG family = IsV6(domain) ? AF_INET6 : AF_INET;
    const DWORD status = IsUdp(domain)
        ? GetExtendedUdpTable(buffer, &size, FALSE, family, UDP_TABLE_OWNER_PID, 0)
        : GetExtendedTcpTable(buffer, &size, FALSE, family, TCP_TABLE_OWNER_PID_LISTENER, 0);
    *bytes = size;
    return status;
}

template <typename Table, typename Row, typename Convert>
ListenerCollectorSnapshot ReadTable(ListenerTableDomain domain,
                                    const ListenerTableReader& reader,
                                    Convert convert) {
    ListenerCollectorSnapshot snapshot;
    constexpr size_t headerBytes = offsetof(Table, table);
    uint32_t size = 0;
    const uint32_t status = reader(domain, nullptr, &size);
    if ((status != ERROR_INSUFFICIENT_BUFFER && status != NO_ERROR) ||
        size < headerBytes || size > kListenerTableMaxBytes) return snapshot;
    for (size_t attempt = 0; attempt < kListenerTableMaxDataCalls; ++attempt) {
        std::vector<uint8_t> buffer(size, 0);
        uint32_t returned = size;
        const uint32_t result = reader(domain, buffer.data(), &returned);
        if (result == ERROR_INSUFFICIENT_BUFFER) {
            if (returned <= size || returned > kListenerTableMaxBytes) return snapshot;
            size = returned;
            continue;
        }
        if (result != NO_ERROR || returned < headerBytes || returned > buffer.size())
            return snapshot;
        DWORD count = 0;
        std::memcpy(&count, buffer.data(), sizeof(count));
        if (count > kListenerTableMaxEntries ||
            count > kListenerRetainedMaxBytes / kListenerEntryChargeBytes ||
            count > (returned - headerBytes) / sizeof(Row)) return snapshot;
        snapshot.listeners.reserve(count);
        for (DWORD i = 0; i < count; ++i) {
            Row row{};
            std::memcpy(&row, buffer.data() + headerBytes + i * sizeof(Row), sizeof(Row));
            snapshot.listeners.push_back(convert(row));
        }
        snapshot.complete = true;
        return snapshot;
    }
    return snapshot;
}
struct ListenerKey {
    std::array<uint8_t, 16> address;
    uint32_t scopeId;
    uint16_t port;
    uint32_t pid;
    uint64_t processStartTime100ns;
    bool operator<(const ListenerKey& other) const {
        return std::tie(address, scopeId, port, pid, processStartTime100ns) <
               std::tie(other.address, other.scopeId, other.port, other.pid,
                        other.processStartTime100ns);
    }
};
struct TrackedListener {
    ListenerCollectorEntry current;
    std::string lastKnownImagePath;
    uint64_t lastKnownStartTime100ns = 0;
};
using ListenerMap = std::map<ListenerKey, TrackedListener>;
static_assert(kListenerEntryChargeBytes >= sizeof(ListenerKey) +
    sizeof(TrackedListener) + 8 * sizeof(void*), "entry charge covers node overhead");
ListenerMap::const_iterator FindEndpoint(const ListenerMap& listeners, ListenerKey key) {
    key.processStartTime100ns = 0;
    auto found = listeners.lower_bound(key);
    if (found == listeners.end()) return found;
    ListenerKey endpoint = found->first;
    endpoint.processStartTime100ns = 0;
    return !(endpoint < key) && !(key < endpoint) ? found : listeners.end();
}
bool ConfirmedReplacement(const ListenerKey& before, const ListenerKey& after) {
    return before.processStartTime100ns != 0 && after.processStartTime100ns != 0 &&
           before.processStartTime100ns != after.processStartTime100ns;
}
bool Track(ListenerTableDomain domain,
           const std::vector<ListenerCollectorEntry>& entries,
           const ListenerMap& previous, ListenerMap& tracked) {
    size_t used = 0;
    if (entries.size() > kListenerTableMaxEntries) return false;
    // Validate before copying paths or constructing nodes; reject whole domain.
    for (const auto& entry : entries) {
        if (!ValidImage(entry.imagePath)) return false;
    }
    for (const auto& input : entries) {
        auto entry = input;
        if (!IsV6(domain)) {
            for (size_t i = 4; i < entry.address.size(); ++i) entry.address[i] = 0;
            entry.scopeId = 0;
        }
        if (entry.processStartTime100ns == 0) entry.imagePath.clear();
        ListenerKey key{entry.address, entry.scopeId, entry.localPort, entry.pid,
                        entry.processStartTime100ns};
        const auto prior = FindEndpoint(previous, key);
        const std::string* lastImage = nullptr;
        uint64_t lastStart = entry.processStartTime100ns;
        if (lastStart != 0) lastImage = &entry.imagePath;
        else if (prior != previous.end()) {
            lastImage = &prior->second.lastKnownImagePath;
            lastStart = prior->second.lastKnownStartTime100ns;
        }
        key.processStartTime100ns = lastStart;
        // Native UDP tables can repeat the same semantic endpoint. Fold exact
        // context duplicates; conflicting PID-instance metadata is ambiguous.
        const auto duplicate = FindEndpoint(tracked, key);
        if (duplicate != tracked.end()) {
            const auto& existing = duplicate->second.current;
            if (existing.processStartTime100ns != entry.processStartTime100ns ||
                existing.imagePath != entry.imagePath) return false;
            continue;
        }
        if (!Charge(used, kListenerEntryChargeBytes + entry.imagePath.size())) return false;
        if (lastImage && !Charge(used, lastImage->size())) return false;
        TrackedListener value;
        if (lastImage) value.lastKnownImagePath = *lastImage;
        value.lastKnownStartTime100ns = lastStart;
        value.current = std::move(entry);
        tracked.emplace(key, std::move(value));
    }
    return true;
}
std::string AddressText(ListenerTableDomain domain,
                        const ListenerCollectorEntry& entry) {
    if (!IsV6(domain)) {
        const auto& ip = entry.address;
        if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0) return "*";
        char text[32];
        std::snprintf(text, sizeof(text), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
        return text;
    }
    char text[INET6_ADDRSTRLEN]{};
    if (!InetNtopA(AF_INET6, const_cast<uint8_t*>(entry.address.data()), text,
                   static_cast<DWORD>(sizeof(text)))) return {};
    std::string address(text);
    if (entry.scopeId != 0) address += "%" + std::to_string(entry.scopeId);
    return address;
}
} // namespace

ListenerCollectorSnapshot QueryListenerCollectorTable(
    ListenerTableDomain domain, ListenerTableReader reader) {
    if (!reader) reader = NativeRead;
    // Reject later PID instances; image and creation time come from one handle.
    const uint64_t sampleStarted = Now100ns();
    ListenerCollectorSnapshot snapshot;
    switch (domain) {
    case ListenerTableDomain::Tcp4:
        snapshot = ReadTable<MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID>(
            domain, reader, [](const MIB_TCPROW_OWNER_PID& row) {
                ListenerCollectorEntry entry;
                std::memcpy(entry.address.data(), &row.dwLocalAddr, 4);
                entry.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                entry.pid = row.dwOwningPid;
                return entry;
            });
        break;
    case ListenerTableDomain::Udp4:
        snapshot = ReadTable<MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID>(
            domain, reader, [](const MIB_UDPROW_OWNER_PID& row) {
                ListenerCollectorEntry entry;
                std::memcpy(entry.address.data(), &row.dwLocalAddr, 4);
                entry.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                entry.pid = row.dwOwningPid;
                return entry;
            });
        break;
    case ListenerTableDomain::Tcp6:
        snapshot = ReadTable<MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID>(
            domain, reader, [](const MIB_TCP6ROW_OWNER_PID& row) {
                ListenerCollectorEntry entry;
                std::memcpy(entry.address.data(), row.ucLocalAddr, 16);
                entry.scopeId = row.dwLocalScopeId;
                entry.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                entry.pid = row.dwOwningPid;
                return entry;
            });
        break;
    case ListenerTableDomain::Udp6:
        snapshot = ReadTable<MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID>(
            domain, reader, [](const MIB_UDP6ROW_OWNER_PID& row) {
                ListenerCollectorEntry entry;
                std::memcpy(entry.address.data(), row.ucLocalAddr, 16);
                entry.scopeId = row.dwLocalScopeId;
                entry.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                entry.pid = row.dwOwningPid;
                return entry;
            });
        break;
    default: return snapshot;
    }
    if (snapshot.complete) {
        size_t used = snapshot.listeners.size() * kListenerEntryChargeBytes;
        std::set<std::tuple<std::array<uint8_t, 16>, uint32_t, uint16_t, uint32_t>> seen;
        size_t unique = 0;
        for (size_t i = 0; i < snapshot.listeners.size(); ++i) {
            const auto& entry = snapshot.listeners[i];
            if (!seen.emplace(entry.address, entry.scopeId, entry.localPort, entry.pid).second)
                continue;
            if (unique != i) snapshot.listeners[unique] = std::move(snapshot.listeners[i]);
            ++unique;
        }
        snapshot.listeners.resize(unique);
        std::map<uint32_t, std::pair<std::string, uint64_t>> contexts;
        for (auto& entry : snapshot.listeners) {
            auto context = contexts.find(entry.pid);
            if (context == contexts.end()) {
                std::string image;
                uint64_t start = 0;
                ResolveProcessContext(entry.pid, sampleStarted, image, start);
                if (!ValidImage(image) ||
                    !Charge(used, kListenerEntryChargeBytes + image.size())) return {};
                context = contexts.emplace(entry.pid,
                    std::make_pair(std::move(image), start)).first;
            }
            // Reserve the path twice: current metadata and historical context
            // in the eventual tracked baseline. Never copy an over-budget path.
            if (!Charge(used, 2 * context->second.first.size())) return {};
            entry.imagePath = context->second.first;
            entry.processStartTime100ns = context->second.second;
        }
    }
    return snapshot;
}

class ListenerCollector : public ICollector {
public:
    ListenerCollector(uint32_t pollMs, ListenerCollectorQuery query)
        : m_pollMs(pollMs == 0 ? 1 : pollMs), m_query(std::move(query)) {}
    ~ListenerCollector() override { Stop(); }
    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) return !m_workerFailed.load();
        if (!bus) return false;
        m_bus = bus;
        m_stop.store(false);
        m_explicitStop.store(false);
        m_workerFailed.store(false);
        for (auto& health : m_domainHealth) {
            health.state.store(0);
            health.seeded.store(false);
            health.listeners.store(0);
        }
        try { m_thread = std::thread(&ListenerCollector::Run, this); }
        catch (...) {
            m_stop.store(true);
            m_bus = nullptr;
            MarkWorkerFailure();
            return false;
        }
        return true;
    }
    void Stop() override {
        m_explicitStop.store(true);
        m_stop.store(true);
        if (m_thread.joinable()) m_thread.join();
    }
    CollectorHealthSnapshot GetHealthSnapshot() const override {
        auto sample = m_health.Snapshot(m_explicitStop.load() ? "stopped" :
            m_workerFailed.load() ? "source_error" : "stopped");
        sample.counters["worker_exceptions"] = m_workerExceptions.load();
        bool pending = false;
        for (size_t i = 0; i < 4; ++i) {
            const std::string prefix = std::string(kDomainNames[i]) + ".";
            const auto& domain = m_domainHealth[i];
            const unsigned state = domain.state.load();
            if (state == 0) pending = true;
            if (state != 0) sample.counters[prefix + "available"] = state == 1 ? 1 : 0;
            sample.counters[prefix + "successful_snapshots"] = domain.successes.load();
            sample.counters[prefix + "source_errors"] = domain.errors.load();
            if (domain.seeded.load()) sample.counters[prefix + "listeners"] = domain.listeners.load();
        }
        if (sample.running && !m_workerFailed.load() && pending)
            sample.state = "starting";
        return sample;
    }
private:
    struct DomainHealth {
        std::atomic<unsigned> state{0};
        std::atomic<uint64_t> successes{0}, errors{0}, listeners{0};
        std::atomic<bool> seeded{false};
    };
    void MarkWorkerFailure() {
        m_workerFailed.store(true);
        m_workerExceptions.fetch_add(1);
        m_health.RecordSourceError();
    }
    void Emit(ListenerTableDomain domain, const ListenerCollectorEntry& listener,
               const char* action) {
        Event event;
        event.type = EDR_EVT_NET_LISTENER;
        event.pid = listener.pid;
        event.source = "listener_monitor";
        event.ts100ns = Now100ns();
        event.processStartTime100ns = listener.processStartTime100ns;
        event.fields[field::kSource] = event.source;
        event.fields[field::kType] = "NET_LISTENER";
        event.fields[field::kListenerAction] = action;
        event.fields[field::kListenerIp] = AddressText(domain, listener);
        event.fields[field::kListenerPort] = std::to_string(listener.localPort);
        event.fields[field::kListenerProtocol] = IsUdp(domain) ? "udp" : "tcp";
        event.fields[field::kListenerPid] = std::to_string(listener.pid);
        event.fields[field::kListenerAddressFamily] = IsV6(domain) ? "ipv6" : "ipv4";
        if (!listener.imagePath.empty() && listener.processStartTime100ns != 0)
            event.fields[field::kListenerProcess] = listener.imagePath;
        m_health.RecordEventSubmitted(!m_bus->Push(event));
    }
    void PollDelay() const {
        uint32_t waited = 0;
        while (waited < m_pollMs && !m_stop.load()) {
            const uint32_t remaining = m_pollMs - waited;
            const uint32_t delay = remaining < 100 ? remaining : 100;
            Sleep(delay);
            waited += delay;
        }
    }
    void Run() {
        m_health.WorkerStarted();
        struct WorkerStopped {
            CollectorRuntimeHealth& health;
            ~WorkerStopped() { health.WorkerStopped(); }
        } stopped{m_health};
        ListenerMap previous[4];
        bool seeded[4]{};
        try {
            while (!m_stop.load()) {
                bool allComplete = true;
                for (size_t i = 0; i < 4 && !m_stop.load(); ++i) {
                    auto snapshot = m_query ? m_query(kDomains[i]) :
                        QueryListenerCollectorTable(kDomains[i]);
                    auto& health = m_domainHealth[i];
                    ListenerMap current;
                    if (!snapshot.complete ||
                        !Track(kDomains[i], snapshot.listeners, previous[i], current)) {
                        health.state.store(2);
                        health.errors.fetch_add(1);
                        allComplete = false;
                        m_health.RecordSourceError();
                        continue;
                    }
                    health.listeners.store(current.size());
                    health.successes.fetch_add(1);
                    health.state.store(1);
                    health.seeded.store(true);
                    if (seeded[i]) {
                        for (const auto& item : current) {
                            const auto prior = FindEndpoint(previous[i], item.first);
                            if (prior == previous[i].end() ||
                                ConfirmedReplacement(prior->first, item.first))
                                Emit(kDomains[i], item.second.current, "added");
                        }
                        for (const auto& item : previous[i]) {
                            const auto now = FindEndpoint(current, item.first);
                            if (now == current.end() ||
                                ConfirmedReplacement(item.first, now->first)) {
                                // The historical process context belongs to the old
                                // listener even if a later context query was denied.
                                auto removed = item.second.current;
                                removed.imagePath = item.second.lastKnownImagePath;
                                removed.processStartTime100ns = item.second.lastKnownStartTime100ns;
                                Emit(kDomains[i], removed, "removed");
                            }
                        }
                    }
                    previous[i] = std::move(current);
                    seeded[i] = true;
                }
                if (m_stop.load()) break;
                if (allComplete) m_health.RecordSnapshotSuccess();
                PollDelay();
            }
        } catch (...) { MarkWorkerFailure(); }
    }
    uint32_t m_pollMs;
    ListenerCollectorQuery m_query;
    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false}, m_explicitStop{false}, m_workerFailed{false};
    std::atomic<uint64_t> m_workerExceptions{0};
    CollectorRuntimeHealth m_health;
    DomainHealth m_domainHealth[4];
};
ICollector* CreateListenerCollector(uint32_t pollMs) {
    return new ListenerCollector(pollMs, {});
}
ICollector* CreateListenerCollector(uint32_t pollMs, ListenerCollectorQuery query) {
    return new ListenerCollector(pollMs, std::move(query));
}
} // namespace edr
