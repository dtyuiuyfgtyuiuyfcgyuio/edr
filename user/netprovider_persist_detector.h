/*
 * netprovider_persist_detector.h - Network Provider DLL persistence
 * detector (T1556.008).
 *
 * Registering a malicious NetworkProvider DLL under
 * HKLM\SYSTEM\CurrentControlSet\Services\<svc>\NetworkProvider (or
 * prepending one to HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\
 * Order) makes npfs/mpr load it into every logon session that touches the
 * network - a boot-persistent credential capture + defense-evasion hook.
 *
 * Consumes EDR_EVT_REG_WRITE and handles BOTH house REG_WRITE shapes
 * (see CLAUDE.md registry contract):
 *   - driver/imonitor shape: kRegKey = bare key path,
 *     kRegValue = value name (value data is not in the event);
 *   - sysmon/reg_watch/reg_baseline snapshot shape: kRegKey = full path
 *     including the value name, kRegValue = the written data.
 *
 * Signals:
 *   - any write to ...\Control\NetworkProvider\Order        -> 85
 *     (driver shape: kRegValue == ProviderOrder; snapshot shape: the
 *     value name is the last key segment)
 *   - NetworkProvider\ProviderPath pointing OUTSIDE the Windows system
 *     directories (System32 / SysWOW64)                     -> 90
 *   - ProviderPath whose data resolves to System32/SysWOW64 is a
 *     legitimate provider install (e.g. LanmanWorkstation)  -> silent
 *   - driver-shape ProviderPath write (no value data in the event)
 *                                                           -> 85
 *     (rare enough to alert for review; the target directory is verified
 *     on the snapshot stream which does carry the data)
 *
 * Score contract: >=75 MALICIOUS, >=55 SUSPICIOUS, below 55 never stamped.
 * Alerts dedup per signal|key inside the dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_NETPROVIDER_PERSIST_DETECTOR_H
#define EDR_NETPROVIDER_PERSIST_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class NetProviderPersistDetector {
public:
    NetProviderPersistDetector(bool enabled, uint32_t minScore,
                               uint32_t dedupWindowSeconds,
                               size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        std::string key;
    };

    bool Analyze(const std::string& regKey, const std::string& regValue,
                 Finding* out) const;
    void Stamp(Event& event, const Finding& finding);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key (signal|lowered key path) -> ts100ns of last alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_NETPROVIDER_PERSIST_DETECTOR_H */
