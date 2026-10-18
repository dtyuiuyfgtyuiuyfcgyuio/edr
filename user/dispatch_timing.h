/*
 * dispatch_timing.h - Per-event-type dispatch latency accounting for the
 * EventBus consumer thread.
 *
 * WHY: EventDispatchSink::OnEvent in user/main.cpp runs the inline
 * detector pipeline from EventBus::ConsumerLoop. This component keeps
 * per-event-type statistics (count / total_us / max_us / slow_count) for the full time
 * spent in that sink, raises a rate-limited stderr warning when one sink
 * dispatch exceeds a threshold, and renders statistics into the health
 * heartbeat's counters channel (a HealthComponent named "dispatch";
 * see health_heartbeat.cpp Snapshot() for the counters rendering). These
 * measurements cover the complete sink call and do not identify an
 * individual detector within it.
 *
 * TIMING CONTRACT: this class performs NO timing of its own. The caller
 * must measure elapsed wall time with QueryPerformanceCounter around the
 * sink invocation, convert the delta to microseconds, and hand the
 * result to RecordEvent(). Typical wrapper at the sink call site:
 *
 *     const bool timeDispatch = timing && timing->Enabled();
 *     LARGE_INTEGER start{}, end{};
 *     if (timeDispatch) QueryPerformanceCounter(&start);
 *     sink->OnEvent(ev);
 *     if (timeDispatch) {
 *         QueryPerformanceCounter(&end);
 *         timing->RecordEvent(ev.type, QpcDeltaUs(start, end));
 *     }
 *
 * Enabled() reads an immutable bool. A disabled scope performs no clock
 * reads or counter updates; keep the QPC calls behind that gate.
 *
 * THREADING: RecordEvent() is single-writer by contract (the EventBus
 * consumer thread is the only caller). Every counter is std::atomic so
 * the health heartbeat thread may call AppendCounters(),
 * TrackedTypes() and TotalEvents() on a live instance; those reads are
 * eventually-consistent snapshots (a slot's count/total/max may be
 * mid-update relative to each other, which is acceptable for
 * observability and never torn).
 *
 * SLOTS: direct-indexed table with kDirectSlots = 64 entries covering
 * event types 0..63. The current EDR_EVT_* set spans 1..58
 * (common/edr_event.h, max EDR_EVT_INCIDENT_CORRELATED = 58), so every type
 * defined today gets a dedicated slot and no LRU eviction is needed;
 * 64 leaves headroom for the next additions. Types >= 64 fold into an
 * "other" aggregate bucket instead of being dropped.
 *
 * HEALTH COUNTERS CHANNEL: health_heartbeat.cpp renders a component's
 * counters map in std::map (lexicographic) order and truncates after 64
 * keys ("counters_truncated" flag). With 58 event types x 4 keys the
 * full table cannot fit, so AppendCounters() self-limits to the channel
 * budget: 6 summary keys (digit-prefixed so they sort before every
 * "dispatch.T.."/"dispatch.other.." key and are never truncated) plus
 * the "other" bucket whenever it is active plus the slowest direct
 * types ranked by max_us until the budget is exhausted. Types that do
 * not fit are summarized in "dispatch.03_omitted_types" - the slowest
 * types, which are the ones that matter for attribution, are always
 * rendered and never silently lost to the host's truncation. To keep
 * the whole 64-key budget, the wiring must give this component its own
 * HealthComponent (same pattern as the "alerts"/"incidents" components)
 * rather than merging its keys into a shared counters map.
 *
 * Key layout (values are decimal strings so the wiring can stoull them
 * into HealthComponent::counters' uint64_t map):
 *   dispatch.00_total_events               all RecordEvent() calls
 *   dispatch.01_tracked_types              distinct buckets with events
 *   dispatch.02_slow_warns                 slow-warning lines emitted
 *   dispatch.03_omitted_types              tracked types not rendered
 *   dispatch.04_slow_events                all over-threshold events, including throttled warnings
 *   dispatch.05_slow_threshold_us          configured threshold; 0 disables slow classification
 *   dispatch.T16.count                     per-type dispatch count
 *   dispatch.T16.total_us                  per-type cumulative us
 *   dispatch.T16.max_us                    per-type worst single dispatch
 *   dispatch.T16.slow_count                per-type over-threshold count
 *   dispatch.other.{count,total_us,max_us,slow_count} types >= 64 folded here
 */
#ifndef EDR_DISPATCH_TIMING_H
#define EDR_DISPATCH_TIMING_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace edr {

struct HealthComponent;

class DispatchTiming {
public:
    /* slowWarnUs == 0 disables slow classification and warnings; otherwise a
     * warning fires when elapsedUs is strictly greater than slowWarnUs.
     * warnCooldownSeconds is the cross-type shared cooldown (default
     * suggestion 30); 0 means no throttling. */
    DispatchTiming(bool enabled, uint32_t slowWarnUs,
                   uint32_t warnCooldownSeconds);

    DispatchTiming(const DispatchTiming&) = delete;
    DispatchTiming& operator=(const DispatchTiming&) = delete;

    /* Consumer thread only. enabled=false: no counter updates. The caller
     * must have measured elapsedUs with QueryPerformanceCounter - see the
     * TIMING CONTRACT above. */
    void RecordEvent(uint16_t eventType, uint64_t elapsedUs);

    /* Health snapshot channel: renders the per-type statistics into the
     * given counters map (unrelated keys are preserved; matching dispatch
     * keys are refreshed). Disabled instance: no-op, the map is left
     * unchanged. Never emits more than kChannelBudget keys - see the
     * HEALTH COUNTERS CHANNEL contract. */
    void AppendCounters(std::map<std::string, std::string>& counters) const;

    /* Immutable configuration gate; lets the caller skip the QPC pair. */
    bool Enabled() const { return m_enabled; }

    /* Distinct buckets that recorded at least one event (the "other"
     * aggregate counts as one bucket). */
    size_t TrackedTypes() const;

    /* Sum of all RecordEvent() calls since construction. */
    uint64_t TotalEvents() const;

private:
    /* Direct-indexed slots for types 0..63; slot kDirectSlots is the
     * aggregate bucket for types >= 64 (current EDR_EVT_* max is 58). */
    static constexpr size_t kDirectSlots = 64;
    static constexpr size_t kSlotCount = kDirectSlots + 1;
    /* Pseudo type id used when ranking/rendering the "other" bucket. */
    static constexpr uint16_t kOtherTypeSentinel = 0xFFFF;
    /* health_heartbeat.cpp truncates a component's counters map after
     * 64 keys; AppendCounters() never emits more than this. */
    static constexpr size_t kChannelBudget = 64;
    static constexpr size_t kSummaryKeys = 6;
    static constexpr size_t kKeysPerType = 4;

    struct Slot {
        std::atomic<uint64_t> count{0};
        std::atomic<uint64_t> totalUs{0};
        std::atomic<uint64_t> maxUs{0};
        std::atomic<uint64_t> slowCount{0};
    };

    void MaybeWarnSlow(uint16_t eventType, uint64_t elapsedUs);

    bool m_enabled;
    uint32_t m_slowWarnUs;
    uint64_t m_warnCooldownMs;
    Slot m_slots[kSlotCount];
    std::atomic<uint64_t> m_totalEvents{0};
    std::atomic<uint64_t> m_slowWarns{0};
    std::atomic<uint64_t> m_slowEvents{0};
    /* steady_clock milliseconds of the last slow warning; 0 sentinel =
     * never warned (mirrors webhook_notifier's failure-log throttle). */
    std::atomic<uint64_t> m_lastWarnMs{0};
};

/* A missing/disabled sampler reports disabled with no numeric counters;
 * an enabled sampler owns a separate bounded dispatch health component. */
HealthComponent SampleDispatchTimingHealth(const DispatchTiming* timing);

} // namespace edr

#endif /* EDR_DISPATCH_TIMING_H */
