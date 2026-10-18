/*
 * dispatch_timing_scope.cpp - QPC-backed dispatch-duration scope.
 */
#include "dispatch_timing_scope.h"

#include <windows.h>

#include <limits>

#include "dispatch_timing.h"

namespace edr {
namespace {

struct QpcFrequency {
    int64_t ticksPerSecond = 0;
    bool available = false;
};

const QpcFrequency& CachedQpcFrequency() noexcept {
    static const QpcFrequency frequency = []() noexcept {
        LARGE_INTEGER value{};
        if (!QueryPerformanceFrequency(&value) || value.QuadPart <= 0)
            return QpcFrequency{};
        return QpcFrequency{value.QuadPart, true};
    }();
    return frequency;
}

uint64_t TicksToMicroseconds(uint64_t ticks, uint64_t frequency) noexcept {
    constexpr uint64_t kMicrosPerSecond = 1000000ULL;
    const uint64_t wholeSeconds = ticks / frequency;
    const uint64_t remainder = ticks % frequency;
    const uint64_t maxValue = (std::numeric_limits<uint64_t>::max)();
    if (wholeSeconds > maxValue / kMicrosPerSecond) return maxValue;

    uint64_t micros = wholeSeconds * kMicrosPerSecond;
    uint64_t fractionalMicros = 0;
    if (remainder <= maxValue / kMicrosPerSecond) {
        fractionalMicros = (remainder * kMicrosPerSecond) / frequency;
    } else {
        /* QPC frequencies are normally small. Keep conversion defined even
         * for an unusually large counter frequency without overflowing an
         * integer intermediate. The fraction is strictly less than 1s. */
        const long double scaled =
            (static_cast<long double>(remainder) * kMicrosPerSecond) /
            static_cast<long double>(frequency);
        fractionalMicros = scaled >= kMicrosPerSecond
            ? kMicrosPerSecond - 1
            : static_cast<uint64_t>(scaled);
    }
    if (fractionalMicros > maxValue - micros) return maxValue;
    micros += fractionalMicros;
    return micros;
}

} // namespace

DispatchTimingScope::DispatchTimingScope(DispatchTiming* timing,
                                         uint16_t eventType) noexcept
    : m_timing(timing), m_eventType(eventType) {
    if (m_timing == nullptr || !m_timing->Enabled()) return;

    m_enabled = true;
    const QpcFrequency& frequency = CachedQpcFrequency();
    LARGE_INTEGER start{};
    if (frequency.available && QueryPerformanceCounter(&start)) {
        m_startCounter = start.QuadPart;
        return;
    }

    /* A steady-clock fallback covers platforms where QPC frequency or the
     * initial counter query is unavailable. It is used only on the enabled
     * path, and only when a QPC start value was not obtained. */
    m_useSteadyClock = true;
    m_startSteady = std::chrono::steady_clock::now();
}

DispatchTimingScope::~DispatchTimingScope() noexcept {
    if (!m_enabled || m_timing == nullptr) return;

    uint64_t elapsedUs = 0;
    if (m_useSteadyClock) {
        const auto elapsed = std::chrono::steady_clock::now() - m_startSteady;
        const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(
            elapsed).count();
        if (micros < 0) return;
        elapsedUs = static_cast<uint64_t>(micros);
    } else {
        const QpcFrequency& frequency = CachedQpcFrequency();
        LARGE_INTEGER end{};
        if (!frequency.available || !QueryPerformanceCounter(&end) ||
            end.QuadPart < m_startCounter)
            return;
        elapsedUs = TicksToMicroseconds(
            static_cast<uint64_t>(end.QuadPart) -
                static_cast<uint64_t>(m_startCounter),
            static_cast<uint64_t>(frequency.ticksPerSecond));
    }

    /* Keep future logging/aggregation changes from escaping a noexcept
     * destructor or replacing an exception already unwinding from OnEvent. */
    try {
        m_timing->RecordEvent(m_eventType, elapsedUs);
    } catch (...) {
        /* Instrumentation must not affect event processing. */
    }
}

} // namespace edr
