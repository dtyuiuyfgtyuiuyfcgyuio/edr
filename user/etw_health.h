/* Read-only ETW logger health query and injectable projection seam. */
#ifndef EDR_ETW_HEALTH_H
#define EDR_ETW_HEALTH_H

#include <functional>
#include <string>

#include <windows.h>

#include "collector.h"

namespace edr {

struct EtwSessionQueryResult {
    ULONG queryStatus = ERROR_GEN_FAILURE;
    ULONG eventsLost = 0;
    ULONG logBuffersLost = 0;
    ULONG realTimeBuffersLost = 0;
};

using EtwSessionQueryFn =
    std::function<EtwSessionQueryResult(const std::wstring& sessionName)>;

/* Query by immutable logger name rather than the collector's mutable session
 * handle. A failed query keeps its status and omits unavailable loss values. */
EtwSessionQueryResult QueryEtwSessionByName(const std::wstring& sessionName);
CollectorHealthSnapshot SampleEtwSessionHealth(
    const std::wstring& sessionName, bool workerActive,
    const EtwSessionQueryFn& query = {});

} // namespace edr

#endif /* EDR_ETW_HEALTH_H */
