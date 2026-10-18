/*
 * com_hijack_detector.h - COM CLSID hijack detector (T1546.015).
 *
 * Monitors COM hijack via HKCU/HKLM\Software\Classes\CLSID\{...}\InprocServer32
 * / LocalServer32 writes. Attackers point the default value at a
 * user-writable DLL/EXE to hijack COM activation.
 *
 * Scores:
 *   - payload in writable dir (Temp/AppData/Public/ProgramData/Downloads) or env var -> 90
 *   - payload outside \windows\system32\ but not writable -> 85
 *   - value name-only (driver shape) -> 75
 *   - system32 payloads and read-only queries stay silent.
 *
 * Dual REG_WRITE shape supported (driver vs sysmon), plus PROCESS_START /
 * POWERSHELL_SCRIPT command plane (`reg add ...\clsid\...\inprocserver32 /d <payload>`).
 */

#ifndef EDR_COM_HIJACK_DETECTOR_H
#define EDR_COM_HIJACK_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ComHijackDetector {
public:
    ComHijackDetector(bool enabled, uint32_t minScore,
                      uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_state.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

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

#endif /* EDR_COM_HIJACK_DETECTOR_H */
