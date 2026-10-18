/*
 * dispatch_timing_scope.h - RAII timing for one inline EventBus dispatch.
 *
 * Construct this at the beginning of the sink call and let it live until
 * normal return or stack unwinding. A null or disabled DispatchTiming skips
 * all clock reads. The destructor never throws, so it cannot replace an
 * exception raised by the sink.
 */
#ifndef EDR_DISPATCH_TIMING_SCOPE_H
#define EDR_DISPATCH_TIMING_SCOPE_H

#include <chrono>
#include <cstdint>

namespace edr {

class DispatchTiming;

class DispatchTimingScope {
public:
    DispatchTimingScope(DispatchTiming* timing, uint16_t eventType) noexcept;
    ~DispatchTimingScope() noexcept;

    DispatchTimingScope(const DispatchTimingScope&) = delete;
    DispatchTimingScope& operator=(const DispatchTimingScope&) = delete;
    DispatchTimingScope(DispatchTimingScope&&) = delete;
    DispatchTimingScope& operator=(DispatchTimingScope&&) = delete;

private:
    DispatchTiming* m_timing = nullptr;
    uint16_t m_eventType = 0;
    bool m_enabled = false;
    bool m_useSteadyClock = false;
    int64_t m_startCounter = 0;
    std::chrono::steady_clock::time_point m_startSteady{};
};

} // namespace edr

#endif /* EDR_DISPATCH_TIMING_SCOPE_H */
