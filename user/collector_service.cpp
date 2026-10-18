/*
 * collector_service.cpp - Windows service change monitoring collector.
 *
 * Polls complete SCM snapshots and emits SERVICE_CHANGE events when services
 * are added, removed, or have a confirmed start-type or binary-path change.
 * Incomplete enumeration is never diffed against the last complete snapshot.
 */
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "collector.h"
#include "collector_runtime_health.h"
#include "collector_service.h"
#include "config.h"
#include "edr_event.h"

namespace edr {

namespace {

constexpr DWORD kServiceEnumPageBytes = 256 * 1024;
constexpr size_t kMaxServiceEnumPages = 256;
constexpr size_t kMaxServicesPerSample = 100000;

class ScHandle {
public:
    explicit ScHandle(SC_HANDLE handle = nullptr) : m_handle(handle) {}
    ~ScHandle() { if (m_handle) CloseServiceHandle(m_handle); }
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
    ScHandle(ScHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = nullptr;
    }
    ScHandle& operator=(ScHandle&& other) noexcept {
        if (this != &other) {
            if (m_handle) CloseServiceHandle(m_handle);
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }
    SC_HANDLE Get() const { return m_handle; }

private:
    SC_HANDLE m_handle;
};

std::string StartTypeName(DWORD startType) {
    switch (startType) {
    case SERVICE_BOOT_START: return "boot";
    case SERVICE_SYSTEM_START: return "system";
    case SERVICE_AUTO_START: return "auto";
    case SERVICE_DEMAND_START: return "manual";
    case SERVICE_DISABLED: return "disabled";
    default: return "unknown";
    }
}

std::string StateName(DWORD state) {
    switch (state) {
    case SERVICE_STOPPED: return "stopped";
    case SERVICE_START_PENDING: return "start_pending";
    case SERVICE_STOP_PENDING: return "stop_pending";
    case SERVICE_RUNNING: return "running";
    case SERVICE_CONTINUE_PENDING: return "continue_pending";
    case SERVICE_PAUSE_PENDING: return "pause_pending";
    case SERVICE_PAUSED: return "paused";
    default: return "unknown";
    }
}

/* A fixed-size page stays within the SCM API's 256 KiB buffer limit. The
 * resume handle advances through complete pages; any lack of progress,
 * duplicate service, or bound exhaustion invalidates the entire sample. */
ServiceCollectorSnapshot EnumerateServices(SC_HANDLE manager) {
    ServiceCollectorSnapshot snapshot;
    std::vector<BYTE> buffer(kServiceEnumPageBytes, 0);
    std::set<std::string> seenNames;
    DWORD resumeHandle = 0;

    for (size_t page = 0; page < kMaxServiceEnumPages; ++page) {
        const DWORD priorResume = resumeHandle;
        DWORD bytesNeeded = 0;
        DWORD servicesReturned = 0;
        const BOOL succeeded = EnumServicesStatusExW(
            manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            buffer.data(), static_cast<DWORD>(buffer.size()), &bytesNeeded,
            &servicesReturned, &resumeHandle, nullptr);
        const DWORD error = succeeded ? ERROR_SUCCESS : GetLastError();
        if (!succeeded && error != ERROR_MORE_DATA) return snapshot;

        const auto* services = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(
            buffer.data());
        for (DWORD i = 0; i < servicesReturned; ++i) {
            ServiceCollectorEntry entry;
            entry.name = WideToUtf8(services[i].lpServiceName);
            entry.displayName = WideToUtf8(services[i].lpDisplayName);
            entry.state = StateName(
                services[i].ServiceStatusProcess.dwCurrentState);
            entry.configAvailable = false;
            if (entry.name.empty() || !seenNames.insert(entry.name).second ||
                snapshot.services.size() >= kMaxServicesPerSample) {
                snapshot.services.clear();
                return snapshot;
            }
            snapshot.services.push_back(std::move(entry));
        }

        if (succeeded) {
            snapshot.complete = true;
            return snapshot;
        }
        if (resumeHandle == priorResume && servicesReturned == 0) {
            snapshot.services.clear();
            return snapshot;
        }
    }

    snapshot.services.clear();
    return snapshot;
}

bool QueryServiceConfigDetails(SC_HANDLE manager,
                               const std::wstring& serviceName,
                               std::string& imagePath,
                               std::string& startType) {
    imagePath.clear();
    startType.clear();
    ScHandle service(OpenServiceW(manager, serviceName.c_str(),
                                   SERVICE_QUERY_CONFIG));
    if (!service.Get()) return false;

    DWORD needed = 0;
    QueryServiceConfigW(service.Get(), nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0)
        return false;

    std::vector<BYTE> buffer(needed);
    if (!QueryServiceConfigW(service.Get(),
            reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data()),
            needed, &needed)) {
        return false;
    }
    const auto* config =
        reinterpret_cast<const QUERY_SERVICE_CONFIGW*>(buffer.data());
    if (config->lpBinaryPathName)
        imagePath = WideToUtf8(config->lpBinaryPathName);
    startType = StartTypeName(config->dwStartType);
    return true;
}

bool EnrichServiceConfigs(SC_HANDLE manager,
                          ServiceCollectorSnapshot& snapshot,
                          uint64_t& queryErrors) {
    queryErrors = 0;
    if (!snapshot.complete) return false;
    for (auto& service : snapshot.services) {
        std::string imagePath;
        std::string startType;
        if (QueryServiceConfigDetails(manager, Utf8ToWide(service.name),
                                      imagePath, startType)) {
            service.imagePath = std::move(imagePath);
            service.startType = std::move(startType);
            service.configAvailable = true;
        } else {
            service.configAvailable = false;
            ++queryErrors;
        }
    }
    return true;
}

struct TrackedService {
    ServiceCollectorEntry current;
    std::string lastKnownStartType;
    std::string lastKnownImagePath;
    bool hasKnownConfig = false;
};

} // namespace

class ServiceCollector : public ICollector {
public:
    ServiceCollector(uint32_t pollMs, ServiceCollectorQuery query)
        : m_pollMs(pollMs), m_query(std::move(query)) {}
    ~ServiceCollector() override { Stop(); }

    bool Start(EventBus* bus) override {
        if (m_thread.joinable()) return true;
        if (bus == nullptr) return false;
        m_bus = bus;
        m_stop.store(false);
        m_explicitStop.store(false);
        m_workerFailed.store(false);
        try {
            m_thread = std::thread(&ServiceCollector::Run, this);
        } catch (...) {
            m_stop.store(true);
            m_bus = nullptr;
            return false;
        }
        return true;
    }

    void Stop() override {
        m_explicitStop.store(true);
        m_stop.store(true);
        if (m_thread.joinable()) m_thread.join();
        if (m_emitCount.load() != 0 || m_errorCount.load() != 0) {
            std::fprintf(stderr,
                "[edr-service] emitted=%llu errors=%llu\n",
                static_cast<unsigned long long>(m_emitCount.load()),
                static_cast<unsigned long long>(m_errorCount.load()));
        }
    }

    CollectorHealthSnapshot GetHealthSnapshot() const override {
        const bool explicitStop = m_explicitStop.load();
        CollectorHealthSnapshot sample = m_health.Snapshot(
            explicitStop ? "stopped" :
            m_workerFailed.load() ? "source_error" : "stopped");
        sample.counters["config_query_errors"] = m_configQueryErrors.load();
        sample.counters["config_unavailable_services"] =
            m_configUnavailableServices.load();
        if (!explicitStop && sample.running && sample.state == "running" &&
            m_configUnavailableServices.load() != 0) {
            sample.state = "config_degraded";
        }
        return sample;
    }

private:
    ServiceCollectorSnapshot QuerySnapshot(SC_HANDLE manager,
                                           uint64_t& configErrors) {
        configErrors = 0;
        if (m_query) return m_query();
        ServiceCollectorSnapshot snapshot = EnumerateServices(manager);
        if (snapshot.complete)
            EnrichServiceConfigs(manager, snapshot, configErrors);
        return snapshot;
    }

    void MarkRecoverableSourceFailure() {
        m_errorCount.fetch_add(1);
        m_health.RecordSourceError();
    }

    void MarkWorkerFailure() {
        m_workerFailed.store(true);
        MarkRecoverableSourceFailure();
    }

    static std::map<std::string, TrackedService> Track(
        const std::vector<ServiceCollectorEntry>& services,
        const std::map<std::string, TrackedService>& previous) {
        std::map<std::string, TrackedService> current;
        for (const auto& service : services) {
            TrackedService tracked;
            tracked.current = service;
            auto prior = previous.find(service.name);
            if (service.configAvailable) {
                tracked.lastKnownStartType = service.startType;
                tracked.lastKnownImagePath = service.imagePath;
                tracked.hasKnownConfig = true;
            } else if (prior != previous.end() && prior->second.hasKnownConfig) {
                /* Keep trusted metadata through transient access failures, but
                 * leave current.configAvailable false for health reporting. */
                tracked.lastKnownStartType = prior->second.lastKnownStartType;
                tracked.lastKnownImagePath = prior->second.lastKnownImagePath;
                tracked.current.startType = tracked.lastKnownStartType;
                tracked.current.imagePath = tracked.lastKnownImagePath;
                tracked.hasKnownConfig = true;
            }
            current.emplace(service.name, std::move(tracked));
        }
        return current;
    }

    void Emit(const ServiceCollectorEntry& service, const char* action) {
        Event event;
        event.type = EDR_EVT_SERVICE_CHANGE;
        event.source = "service_monitor";
        FILETIME now = {};
        GetSystemTimePreciseAsFileTime(&now);
        event.ts100ns = (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
                        now.dwLowDateTime;
        event.fields[field::kSource] = event.source;
        event.fields[field::kType] = "SERVICE_CHANGE";
        event.fields[field::kServiceAction] = action;
        event.fields[field::kServiceName] = service.name;
        if (!service.displayName.empty())
            event.fields[field::kServiceDisplayName] = service.displayName;
        if (!service.startType.empty())
            event.fields[field::kServiceStartType] = service.startType;
        if (!service.state.empty())
            event.fields[field::kServiceState] = service.state;
        if (!service.imagePath.empty())
            event.fields[field::kServiceImagePath] = service.imagePath;

        if (m_bus) {
            const bool overflowObserved = !m_bus->Push(event);
            /* Push(false) means the previous queued event was evicted; the
             * current service event was still submitted to the bus. */
            m_health.RecordEventSubmitted(overflowObserved);
            m_emitCount.fetch_add(1);
        }
    }

    void DiffAndEmit(const std::map<std::string, TrackedService>& previous,
                     const std::vector<ServiceCollectorEntry>& services) {
        const auto current = Track(services, previous);
        for (const auto& item : current) {
            auto prior = previous.find(item.first);
            if (prior == previous.end()) {
                Emit(item.second.current, "added");
                continue;
            }
            const TrackedService& now = item.second;
            const TrackedService& before = prior->second;
            if (now.current.configAvailable && before.hasKnownConfig &&
                (now.current.startType != before.lastKnownStartType ||
                 now.current.imagePath != before.lastKnownImagePath)) {
                Emit(now.current, "modified");
            }
        }
        for (const auto& item : previous) {
            if (current.find(item.first) == current.end())
                Emit(item.second.current, "removed");
        }
        m_previous = current;
    }

    void PollDelay() const {
        for (uint32_t waited = 0;
             waited < m_pollMs && !m_stop.load(); waited += 100) {
            Sleep(100);
        }
    }

    void Run() {
        m_health.WorkerStarted();
        struct WorkerStopped {
            CollectorRuntimeHealth& health;
            ~WorkerStopped() { health.WorkerStopped(); }
        } workerStopped{m_health};

        ScHandle manager;
        try {
            if (!m_query) {
                manager = ScHandle(OpenSCManagerW(
                    nullptr, nullptr,
                    SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE));
                if (!manager.Get()) {
                    const DWORD error = GetLastError();
                    std::fprintf(stderr,
                        "[edr-service] OpenSCManager failed: %lu\n",
                        static_cast<unsigned long>(error));
                    MarkWorkerFailure();
                    return;
                }
            }

            bool haveBaseline = false;
            while (!m_stop.load()) {
                uint64_t configErrors = 0;
                ServiceCollectorSnapshot sample =
                    QuerySnapshot(manager.Get(), configErrors);
                if (!sample.complete) {
                    MarkRecoverableSourceFailure();
                } else {
                    m_health.RecordSnapshotSuccess();
                    m_configQueryErrors.fetch_add(configErrors);
                    uint64_t unavailable = 0;
                    for (const auto& service : sample.services)
                        if (!service.configAvailable) ++unavailable;
                    m_configUnavailableServices.store(unavailable);

                    if (haveBaseline) {
                        DiffAndEmit(m_previous, sample.services);
                    } else {
                        m_previous = Track(sample.services, {});
                        haveBaseline = true;
                    }
                }
                PollDelay();
            }
        } catch (...) {
            MarkWorkerFailure();
        }
    }

    uint32_t m_pollMs;
    ServiceCollectorQuery m_query;
    EventBus* m_bus = nullptr;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_explicitStop{false};
    std::atomic<bool> m_workerFailed{false};
    std::atomic<uint64_t> m_emitCount{0};
    std::atomic<uint64_t> m_errorCount{0};
    std::atomic<uint64_t> m_configQueryErrors{0};
    std::atomic<uint64_t> m_configUnavailableServices{0};
    CollectorRuntimeHealth m_health;
    std::map<std::string, TrackedService> m_previous;
};

ICollector* CreateServiceCollector(uint32_t pollMs) {
    return new ServiceCollector(pollMs, {});
}

ICollector* CreateServiceCollector(uint32_t pollMs,
                                   ServiceCollectorQuery query) {
    return new ServiceCollector(pollMs, std::move(query));
}

} // namespace edr
