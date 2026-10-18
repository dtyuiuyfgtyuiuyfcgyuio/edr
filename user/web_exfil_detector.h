/*
 * web_exfil_detector.h - Exfiltration over web service detector
 * (T1567).
 *
 * Scores command/script-plane uploads to third-party web services
 * that bypass traditional C2 channels:
 *   - rclone copy/sync/move to a configured remote                -> 90
 *   - Discord webhook POST                                        -> 85
 *   - Telegram Bot API sendDocument / sendMessage                 -> 85
 *   - MEGA / megacmd put/copy upload                              -> 80
 *   - pastebin / transfer.sh / file.io / gofile sinks             -> 75
 *   - curl/Invoke-WebRequest -InFile / --data-binary POST/PUT     -> 70
 *
 * Complements data_exfiltration (volume/entropy/DNS-tunnel plane)
 * and static rule EDR-287 (curl -T / wget --post-file). Plain
 * downloads and rclone config inspection stay silent.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_WEB_EXFIL_DETECTOR_H
#define EDR_WEB_EXFIL_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class WebExfilDetector {
public:
    WebExfilDetector(bool enabled, uint32_t minScore,
                     uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
    };

    bool Analyze(const std::string& lower, const std::string& imageLower,
                 Finding* out) const;
    void Stamp(Event& event, const Finding& finding,
               const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_WEB_EXFIL_DETECTOR_H */
