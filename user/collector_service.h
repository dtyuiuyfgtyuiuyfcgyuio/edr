/*
 * collector_service.h - Windows service change monitoring collector.
 *
 * Polls the service control manager database and emits SERVICE_CHANGE
 * events when services are added, removed, or modified. Detects service
 * persistence (MITRE T1543.003).
 */
#ifndef EDR_COLLECTOR_SERVICE_H
#define EDR_COLLECTOR_SERVICE_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace edr {

class ICollector;

/* Narrow sampling seam for deterministic tests. A failed or partial sample
 * must set complete=false; its services vector is never diffed. Config query
 * failures are local to a service and leave configAvailable=false. */
struct ServiceCollectorEntry {
    std::string name;
    std::string displayName;
    std::string state;
    std::string startType;
    std::string imagePath;
    bool configAvailable = true;
};

struct ServiceCollectorSnapshot {
    bool complete = false;
    std::vector<ServiceCollectorEntry> services;
};

/* Test providers run on the collector worker thread. Throwing models a fatal
 * source initialization/worker failure; incomplete results are recoverable. */
using ServiceCollectorQuery =
    std::function<ServiceCollectorSnapshot()>;

ICollector* CreateServiceCollector(uint32_t pollMs);
ICollector* CreateServiceCollector(uint32_t pollMs,
                                   ServiceCollectorQuery query);

} // namespace edr

#endif /* EDR_COLLECTOR_SERVICE_H */
