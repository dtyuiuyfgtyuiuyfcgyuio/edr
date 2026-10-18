/*
 * file_assoc_detector.h - File association / default handler hijack
 * detector (T1546.001 Change Default File Association).
 *
 * An attacker rewrites which verb handler runs when a file with a given
 * extension is double-clicked, e.g. by setting
 *   HKCU\Software\Classes\.txt / (default)  ->  txtfile\shell\open\command
 *   HKCU\Software\Classes\txtfile\shell\open\command\(default) -> payload
 *   HKCR\.exe, HKCR\exefile, HKCR\scrfile, or generic <ext>\OpenWithProgids
 * Scoring:
 *   - command in association points at interpreter             -> 90
 *   - command in user-writable path                           -> 90
 *   - command with other payload extension                      -> 85
 *   - ftype/assoc command line without data (slot write)        -> 75
 *   - stock system32 open command stays silent; read-only
 *     queries (assoc, ftype <ext> without assignment) stay silent
 */
#ifndef EDR_FILE_ASSOC_DETECTOR_H
#define EDR_FILE_ASSOC_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include "edr_event.h"
#include "event_bus.h"

namespace edr {
class FileAssocDetector {
public:
    FileAssocDetector(bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds, size_t stateCapacity);
    void Enrich(Event& event);
    static bool Inspects(uint16_t type);
private:
    struct Finding { uint32_t score=0; const char* signal=""; };
    static bool ClassifyPayload(const std::string& data, Finding* out);
    void Stamp(Event& event, const Finding& finding, const std::string& key);
    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;
    std::unordered_map<std::string,uint64_t> m_lastAlert;
    static constexpr uint64_t kFiletimeTicksPerSecond=10000000ULL;
};
} // namespace edr
#endif
