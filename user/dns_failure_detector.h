#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>

#include "edr_event.h"

namespace edr {

struct Event;

class DnsFailureDetector {
public:
    DnsFailureDetector(bool enabled, uint32_t windowSeconds,
                       size_t stateCapacity, uint32_t minQueries,
                       uint32_t minDistinctNames, uint32_t minFailurePercent,
                       uint32_t minHighEntropyFailures);

    static bool Inspects(uint32_t eventType);
    void Enrich(Event& event);
    size_t StateCount() const { return states_.size(); }

private:
    struct Observation {
        uint64_t timestamp;
        std::string name;
        bool failed;
        bool highEntropy;
    };
    struct State {
        std::deque<Observation> observations;
        uint64_t latestTimestamp = 0;
        uint64_t lastSeen = 0;
        uint32_t emittedScore = 0;
    };

    bool enabled_;
    uint64_t windowTicks_;
    size_t stateCapacity_;
    uint32_t minQueries_;
    uint32_t minDistinctNames_;
    uint32_t minFailurePercent_;
    uint32_t minHighEntropyFailures_;
    std::unordered_map<std::string, State> states_;
};

} // namespace edr
