/*
 * iso_mount_detector.h - Disk-image mount abuse detector (T1553.005).
 *
 * Detects ISO / IMG / VHD / VHDX mounting abused to dodge
 * Mark-of-the-Web: Mount-DiskImage (writable-path staging scores
 * highest), Explorer double-click mounts, and PowerShell script-body
 * equivalents. Read-only inspection (dism /get-imageinfo, Get-DiskImage
 * queries, dismount cleanup) stays silent. Complements
 * MotwBypassDetector (EDR-376), which covers Zone.Identifier stripping.
 */

#ifndef EDR_ISO_MOUNT_DETECTOR_H
#define EDR_ISO_MOUNT_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include "edr_event.h"
#include "event_bus.h"

namespace edr {
class IsoMountDetector {
public:
    IsoMountDetector(bool enabled, uint32_t minScore, uint32_t dedupWindowSeconds, size_t stateCapacity);
    void Enrich(Event& event);
    static bool Inspects(uint16_t type);
    size_t StateCount() const { return m_state.size(); }
private:
    struct Finding { uint32_t score=0; const char* signal=""; };
    static bool ClassifyPayload(const std::string& cmdLower, const std::string& imageLower, Finding* out);
    void Stamp(Event& e,const Finding& f,const std::string& k);
    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_capacity;
    std::unordered_map<std::string,uint64_t> m_state;
    static constexpr uint64_t kFiletimeTicksPerSecond=10000000ULL;
};
} // namespace edr
#endif
