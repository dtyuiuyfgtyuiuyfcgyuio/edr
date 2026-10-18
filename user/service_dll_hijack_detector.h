/*
 * service_dll_hijack_detector.h - ServiceDll hijack detector (T1574.011).
 *
 * Monitors writes to the ServiceDll registry value under
 * HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters, the mechanism
 * svchost uses to locate its implementation DLL. A rewrite pointing away
 * from system32 is one of the stealthier persistence planes: the service
 * host is an inbox binary, so only the value data betrays the hijack.
 *
 * Scores the payload DATA assigned to ServiceDll:
 *   - DLL in a user-writable directory (Temp/AppData/Public/
 *     ProgramData/Downloads) or an environment-variable path   -> 90
 *   - DLL elsewhere outside \windows\system32\                 -> 85
 *   - value name-only observation (driver shape carries no
 *     data)                                                    -> 75
 *   - svchost-group Parameters keys writing ServiceDll with
 *     no data observed (command plane)                         -> 75
 *
 * Read-only queries (reg query / Get-ItemProperty) and ServiceDll writes
 * whose data stays inside \windows\system32\ (stock netsvcs
 * implementations) stay silent.
 *
 * Honors the REG_WRITE dual shape: driver/imonitor events carry the bare
 * key plus the value NAME, sysmon/reg_watch snapshots carry the full key
 * including the value name plus the DATA. Complements svc_path_abuse
 * (ImagePath plane: the EXE) and registry_persistence (Run/IFEO plane).
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_SERVICE_DLL_HIJACK_DETECTOR_H
#define EDR_SERVICE_DLL_HIJACK_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ServiceDllHijackDetector {
public:
    ServiceDllHijackDetector(bool enabled, uint32_t minScore,
                             uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_state.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    /* Grades the payload DATA assigned to ServiceDll. Returns false when
     * the data is a stock system32 implementation. */
    static bool ClassifyPayload(const std::string& data, Finding* out);

    void Stamp(Event& event, const Finding& finding, const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_capacity;
    std::unordered_map<std::string, uint64_t> m_state;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_SERVICE_DLL_HIJACK_DETECTOR_H */
