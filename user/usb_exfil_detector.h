/*
 * usb_exfil_detector.h - Removable-media exfiltration detector (T1025).
 *
 * Learns removable drive letters from USB_DEVICE events, then correlates
 * FILE_CREATE/FILE_RENAME activity on those drives: bulk copies and copies
 * of sensitive documents (doc/xls/pdf/db/key stores/...) are scored and
 * stamped with usb_exfil_* fields. A per-drive dedup window suppresses
 * repeated alerts for the same copy session.
 */
#ifndef EDR_USB_EXFIL_DETECTOR_H
#define EDR_USB_EXFIL_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class UsbExfilDetector {
public:
    UsbExfilDetector(bool enabled, uint32_t windowSeconds,
                     size_t stateCapacity, uint32_t minFileCount,
                     uint32_t dedupSeconds);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_drives.size(); }

private:
    struct DriveState {
        uint64_t lastSeen100ns = 0;
        uint64_t lastStamp100ns = 0;
        std::map<std::string, uint64_t> files;
    };

    static std::string DriveLetterOf(const std::string& path);
    bool IsSensitiveExtension(const std::string& path) const;
    void PurgeExpired(uint64_t now100ns);
    void WriteState(Event& event, const DriveState& state,
                    const std::string& drive, uint32_t count,
                    uint32_t sensitiveCount) const;

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minFileCount;
    uint64_t m_dedup100ns;
    uint32_t m_dedupSeconds;
    std::unordered_map<std::string, uint64_t> m_removable;
    std::unordered_map<std::string, DriveState> m_drives;
};

} // namespace edr

#endif /* EDR_USB_EXFIL_DETECTOR_H */
