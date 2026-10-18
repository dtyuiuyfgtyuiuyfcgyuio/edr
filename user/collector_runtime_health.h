/*
 * collector_runtime_health.h - small atomic health accumulator for polling and
 * worker-based collectors. The counters describe observations made by the
 * collector; unavailable source-specific metrics are deliberately omitted.
 */
#ifndef EDR_COLLECTOR_RUNTIME_HEALTH_H
#define EDR_COLLECTOR_RUNTIME_HEALTH_H

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <map>
#include <string>

#include "collector.h"
#include "edr_event.h"

namespace edr {

class CollectorRuntimeHealth {
public:
    void WorkerStarted() noexcept { m_workerActive.store(true); }
    void WorkerStopped() noexcept { m_workerActive.store(false); }

    void RecordSourceError(uint64_t count = 1) noexcept {
        m_sourceErrors.fetch_add(count);
        m_sourceState.store(2);
    }
    void RecordParseError(uint64_t count = 1) noexcept {
        m_parseErrors.fetch_add(count);
    }
    void MarkSourceAvailable() noexcept { m_sourceState.store(1); }
    void ResetSourceState() noexcept { m_sourceState.store(0); }
    void RecordSnapshotSuccess() noexcept {
        m_successfulSnapshots.fetch_add(1);
        FILETIME now = {};
        GetSystemTimePreciseAsFileTime(&now);
        m_lastSuccess100ns.store(
            (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
            now.dwLowDateTime);
        MarkSourceAvailable();
    }

    /* Push(false) means an older queued event was evicted; this event was
     * still submitted. Keep submitted count separate from overflow evidence. */
    void RecordEventSubmitted(bool pushReportedOverflow) noexcept {
        m_eventsSubmitted.fetch_add(1);
        if (pushReportedOverflow) m_busOverflowObserved.fetch_add(1);
    }

    void ObserveKernelQueueDropped(uint32_t wireCount) noexcept {
        m_kernelQueueDropped.store(wireCount);
        m_kernelQueueCounterObserved.store(true);
    }

    CollectorHealthSnapshot Snapshot(
        const std::string& stoppedState = "stopped",
        uint64_t activeWatches = 0,
        bool includeActiveWatches = false,
        bool activeWatchesSettled = true) const {
        CollectorHealthSnapshot sample;
        sample.supported = true;
        sample.running = m_workerActive.load();
        const unsigned sourceState = m_sourceState.load();
        sample.state = !sample.running ? stoppedState :
            includeActiveWatches && !activeWatchesSettled ? "starting" :
            includeActiveWatches && activeWatches == 0 ? "no_active_watches" :
            sourceState == 2 ? "source_error" :
            sourceState == 1 ? "running" : "starting";
        sample.sourceErrors = m_sourceErrors.load();
        sample.parseErrors = m_parseErrors.load();
        sample.busDropped = m_busOverflowObserved.load();
        sample.eventsPushed = m_eventsSubmitted.load();
        sample.lastSuccess100ns = m_lastSuccess100ns.load();
        sample.countersAvailable = true;
        sample.counters = {
            {"worker_active", sample.running ? 1u : 0u},
            {"source_errors", sample.sourceErrors},
            {"parse_errors", sample.parseErrors},
            {"bus_overflow_observed", sample.busDropped},
            {"events_submitted", sample.eventsPushed},
            {"successful_snapshots", m_successfulSnapshots.load()},
        };
        if (includeActiveWatches)
            sample.counters.emplace("active_watches", activeWatches);
        if (sourceState != 0) {
            sample.counters.emplace("source_available", sourceState == 1 ? 1u : 0u);
        }
        if (m_kernelQueueCounterObserved.load()) {
            /* The wire field is ULONG. Export its last observed value and
             * explicitly avoid claiming a non-wrapping lifetime total. */
            sample.counters.emplace("kernel_queue_dropped",
                                    m_kernelQueueDropped.load());
            sample.counters.emplace("kernel_queue_dropped_counter_bits", 32);
        }
        return sample;
    }

private:
    std::atomic<bool> m_workerActive{false};
    std::atomic<uint64_t> m_sourceErrors{0};
    std::atomic<uint64_t> m_parseErrors{0};
    std::atomic<uint64_t> m_busOverflowObserved{0};
    std::atomic<uint64_t> m_eventsSubmitted{0};
    std::atomic<uint64_t> m_successfulSnapshots{0};
    std::atomic<uint64_t> m_lastSuccess100ns{0};
    /* 0=not yet sampled, 1=most recent source operation succeeded,
     * 2=most recent source operation failed. */
    std::atomic<unsigned> m_sourceState{0};
    std::atomic<bool> m_kernelQueueCounterObserved{false};
    std::atomic<uint32_t> m_kernelQueueDropped{0};
};

inline void ObserveDriverStatsHealth(CollectorRuntimeHealth& health,
                                     uint16_t eventType,
                                     uint32_t reserved) noexcept {
    if (eventType == EDR_EVT_STATS)
        health.ObserveKernelQueueDropped(reserved);
}

} // namespace edr

#endif /* EDR_COLLECTOR_RUNTIME_HEALTH_H */
