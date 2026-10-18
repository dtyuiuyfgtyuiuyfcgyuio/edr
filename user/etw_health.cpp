#include "etw_health.h"

#include <evntrace.h>

#include <algorithm>
#include <cstdint>
#include <exception>
#include <vector>

namespace edr {

EtwSessionQueryResult QueryEtwSessionByName(const std::wstring& sessionName) {
    EtwSessionQueryResult result;
    constexpr size_t kMaxSessionNameChars = 1024;
    constexpr size_t kMaxReturnedPathChars = 1024;
    if (sessionName.empty() || sessionName.find(L'\0') != std::wstring::npos ||
        sessionName.size() > kMaxSessionNameChars) {
        result.queryStatus = ERROR_INVALID_NAME;
        return result;
    }

    const ULONG bufferSize = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) +
        (kMaxSessionNameChars + 1) * sizeof(wchar_t) +
        (kMaxReturnedPathChars + 1) * sizeof(wchar_t));
    std::vector<uint8_t> buffer(bufferSize, 0);
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
    properties->Wnode.BufferSize = bufferSize;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    properties->LogFileNameOffset = static_cast<ULONG>(
        sizeof(EVENT_TRACE_PROPERTIES) +
        (kMaxSessionNameChars + 1) * sizeof(wchar_t));
    auto* loggerName = reinterpret_cast<wchar_t*>(buffer.data() +
        properties->LoggerNameOffset);
    std::copy(sessionName.begin(), sessionName.end(), loggerName);
    loggerName[sessionName.size()] = L'\0';

    /* SessionHandle zero is intentional: the session name is immutable after
     * successful collector startup and avoids races with Stop's handle reset. */
    result.queryStatus = ControlTraceW(0, sessionName.c_str(), properties,
                                       EVENT_TRACE_CONTROL_QUERY);
    if (result.queryStatus == ERROR_SUCCESS) {
        result.eventsLost = properties->EventsLost;
        result.logBuffersLost = properties->LogBuffersLost;
        result.realTimeBuffersLost = properties->RealTimeBuffersLost;
    }
    return result;
}

CollectorHealthSnapshot SampleEtwSessionHealth(
    const std::wstring& sessionName, bool workerActive,
    const EtwSessionQueryFn& query) {
    EtwSessionQueryResult result;
    try {
        result = query ? query(sessionName) : QueryEtwSessionByName(sessionName);
    } catch (...) {
        result.queryStatus = ERROR_GEN_FAILURE;
        result.eventsLost = 0;
        result.logBuffersLost = 0;
        result.realTimeBuffersLost = 0;
    }

    CollectorHealthSnapshot sample;
    sample.supported = true;
    sample.running = workerActive;
    sample.countersAvailable = true;
    const bool querySucceeded = result.queryStatus == ERROR_SUCCESS;
    sample.state = !querySucceeded ? "session_query_failed" :
        workerActive ? "running" : "stopped";
    sample.counters = {
        {"worker_active", workerActive ? 1ULL : 0ULL},
        {"session_query_available", querySucceeded ? 1ULL : 0ULL},
        {"session_query_status", result.queryStatus},
    };
    if (querySucceeded) {
        sample.counters.emplace("events_lost", result.eventsLost);
        sample.counters.emplace("log_buffers_lost", result.logBuffersLost);
        sample.counters.emplace("realtime_buffers_lost", result.realTimeBuffersLost);
    }
    return sample;
}

} // namespace edr
