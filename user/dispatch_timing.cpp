/*
 * dispatch_timing.cpp - per-event-type dispatch latency accounting.
 *
 * All timing happens at the caller (QueryPerformanceCounter around the
 * sink dispatch, per the TIMING CONTRACT in dispatch_timing.h); this
 * translation unit only aggregates counters, throttles slow warnings
 * and renders the health counters channel.
 */
#include "dispatch_timing.h"
#include "health_heartbeat.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <vector>

namespace edr {

namespace {

uint64_t SteadyNowMs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

} // namespace

DispatchTiming::DispatchTiming(bool enabled, uint32_t slowWarnUs,
                               uint32_t warnCooldownSeconds)
    : m_enabled(enabled),
      m_slowWarnUs(slowWarnUs),
      m_warnCooldownMs(static_cast<uint64_t>(warnCooldownSeconds) * 1000ULL) {}

void DispatchTiming::RecordEvent(uint16_t eventType, uint64_t elapsedUs) {
    if (!m_enabled) return; /* disabled fast path: single relaxed load */

    Slot& slot =
        m_slots[eventType < kDirectSlots ? eventType : kDirectSlots];
    slot.count.fetch_add(1, std::memory_order_relaxed);
    slot.totalUs.fetch_add(elapsedUs, std::memory_order_relaxed);
    uint64_t currentMax = slot.maxUs.load(std::memory_order_relaxed);
    while (currentMax < elapsedUs &&
           !slot.maxUs.compare_exchange_weak(currentMax, elapsedUs,
               std::memory_order_relaxed, std::memory_order_relaxed)) {
    }
    m_totalEvents.fetch_add(1, std::memory_order_relaxed);

    if (m_slowWarnUs != 0 && elapsedUs > m_slowWarnUs) {
        slot.slowCount.fetch_add(1, std::memory_order_relaxed);
        m_slowEvents.fetch_add(1, std::memory_order_relaxed);
        MaybeWarnSlow(eventType, elapsedUs);
    }
}

void DispatchTiming::MaybeWarnSlow(uint16_t eventType, uint64_t elapsedUs) {
    const uint64_t nowMs = SteadyNowMs();
    uint64_t last = m_lastWarnMs.load(std::memory_order_relaxed);
    /* The cooldown is shared across event types: one expensive sink
     * dispatch must not flood stderr when several types are slow in the
     * same window.
     * 0 sentinel = never warned (steady clock can read below the
     * cooldown right after boot, so the sentinel is checked explicitly,
     * mirroring webhook_notifier's failure-log throttle). */
    if (m_warnCooldownMs != 0 && last != 0 &&
        nowMs - last < m_warnCooldownMs)
        return;
    if (!m_lastWarnMs.compare_exchange_strong(last, nowMs,
            std::memory_order_relaxed, std::memory_order_relaxed))
        return;
    m_slowWarns.fetch_add(1, std::memory_order_relaxed);
    std::fprintf(stderr,
        "[edr-dispatch] slow dispatch: type=T%02u elapsed_us=%llu "
        "threshold_us=%u total_events=%llu\n",
        static_cast<unsigned>(eventType),
        static_cast<unsigned long long>(elapsedUs),
        static_cast<unsigned>(m_slowWarnUs),
        static_cast<unsigned long long>(
            m_totalEvents.load(std::memory_order_relaxed)));
}

size_t DispatchTiming::TrackedTypes() const {
    size_t tracked = 0;
    for (size_t i = 0; i < kSlotCount; ++i)
        if (m_slots[i].count.load(std::memory_order_relaxed) > 0) ++tracked;
    return tracked;
}

uint64_t DispatchTiming::TotalEvents() const {
    return m_totalEvents.load(std::memory_order_relaxed);
}

HealthComponent SampleDispatchTimingHealth(const DispatchTiming* timing) {
    HealthComponent component;
    component.name = "dispatch";
    component.state = "disabled";
    if (timing == nullptr || !timing->Enabled()) return component;
    component.state = "running";
    component.countersAvailable = true;
    std::map<std::string, std::string> counters;
    timing->AppendCounters(counters);
    for (const auto& counter : counters)
        component.counters.emplace(counter.first, std::stoull(counter.second));
    return component;
}

void DispatchTiming::AppendCounters(
    std::map<std::string, std::string>& counters) const {
    if (!m_enabled) return;

    struct ActiveBucket {
        uint16_t type; /* kOtherTypeSentinel = "other" aggregate */
        uint64_t count;
        uint64_t totalUs;
        uint64_t maxUs;
        uint64_t slowCount;
    };
    std::vector<ActiveBucket> active;
    active.reserve(kSlotCount);
    for (size_t i = 0; i < kSlotCount; ++i) {
        const uint64_t count =
            m_slots[i].count.load(std::memory_order_relaxed);
        if (count == 0) continue;
        active.push_back(ActiveBucket{
            i == kDirectSlots ? kOtherTypeSentinel
                              : static_cast<uint16_t>(i),
            count,
            m_slots[i].totalUs.load(std::memory_order_relaxed),
            m_slots[i].maxUs.load(std::memory_order_relaxed),
            m_slots[i].slowCount.load(std::memory_order_relaxed)});
    }
    /* Rank by worst single dispatch, then by aggregate cost; type id as
     * the deterministic tie-break (the "other" sentinel sorts last). */
    std::sort(active.begin(), active.end(),
        [](const ActiveBucket& a, const ActiveBucket& b) {
            if (a.maxUs != b.maxUs) return a.maxUs > b.maxUs;
            if (a.totalUs != b.totalUs) return a.totalUs > b.totalUs;
            return a.type < b.type;
        });

    /* Digit-prefixed summary keys sort before "dispatch.T.."/"dispatch."
     * "other.." keys in std::map order, so the host's 64-key truncation
     * can never drop them. */
    counters["dispatch.00_total_events"] =
        std::to_string(m_totalEvents.load(std::memory_order_relaxed));
    counters["dispatch.01_tracked_types"] =
        std::to_string(active.size());
    counters["dispatch.02_slow_warns"] =
        std::to_string(m_slowWarns.load(std::memory_order_relaxed));
    counters["dispatch.04_slow_events"] =
        std::to_string(m_slowEvents.load(std::memory_order_relaxed));
    counters["dispatch.05_slow_threshold_us"] = std::to_string(m_slowWarnUs);

    auto label = [](uint16_t type) {
        if (type == kOtherTypeSentinel) return std::string("other");
        std::string text = "T";
        if (type < 10) text += '0';
        text += std::to_string(type);
        return text;
    };
    auto render = [&counters, &label](const ActiveBucket& bucket) {
        const std::string prefix = "dispatch." + label(bucket.type);
        counters[prefix + ".count"] = std::to_string(bucket.count);
        counters[prefix + ".total_us"] = std::to_string(bucket.totalUs);
        counters[prefix + ".max_us"] = std::to_string(bucket.maxUs);
        counters[prefix + ".slow_count"] = std::to_string(bucket.slowCount);
    };

    /* Channel budget: 64 keys minus the 6 summary keys. The "other"
     * bucket is always rendered when active (it aggregates types the
     * slots cannot name); the remainder goes to the slowest direct
     * types in rank order, everything else is counted as omitted. */
    size_t typeKeysLeft = kChannelBudget - kSummaryKeys;
    size_t omitted = 0;
    for (const ActiveBucket& bucket : active) {
        if (bucket.type != kOtherTypeSentinel) continue;
        if (typeKeysLeft >= kKeysPerType) {
            render(bucket);
            typeKeysLeft -= kKeysPerType;
        }
        break;
    }
    for (const ActiveBucket& bucket : active) {
        if (bucket.type == kOtherTypeSentinel) continue;
        if (typeKeysLeft >= kKeysPerType) {
            render(bucket);
            typeKeysLeft -= kKeysPerType;
        } else {
            ++omitted;
        }
    }
    counters["dispatch.03_omitted_types"] = std::to_string(omitted);
}

} // namespace edr
