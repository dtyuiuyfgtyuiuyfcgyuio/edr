/*
 * collector.h - Collector interface. Each collector owns its own worker
 * thread(s) and pushes normalized events into the EventBus.
 */
#ifndef EDR_COLLECTOR_H
#define EDR_COLLECTOR_H

#include <map>

#include "event_bus.h"

namespace edr {

struct CollectorHealthSnapshot {
    bool supported = false;
    bool running = false;
    size_t queuePending = 0;
    uint64_t queueDropped = 0;
    uint64_t renderErrors = 0;
    uint64_t parseErrors = 0;
    uint64_t busDropped = 0;
    uint64_t sourceErrors = 0;
    uint64_t eventsPushed = 0;
    uint64_t lastSuccess100ns = 0;
    std::string replayState;
    // Optional source-specific counters, e.g. ETW session loss. A failed query
    // omits unavailable values instead of inventing zero losses.
    bool countersAvailable = false;
    std::map<std::string, uint64_t> counters;
    std::string state;
};

class ICollector {
public:
    virtual ~ICollector() = default;
    virtual bool Start(EventBus* bus) = 0; /* false = unavailable, degraded */
    virtual void Stop() = 0;
    /* Unsupported is explicit; successful Start alone does not prove health. */
    virtual CollectorHealthSnapshot GetHealthSnapshot() const { return {}; }
};

} // namespace edr

#endif /* EDR_COLLECTOR_H */
