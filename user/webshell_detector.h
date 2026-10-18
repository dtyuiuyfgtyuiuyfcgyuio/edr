/*
 * webshell_detector.h - Web shell staging detector (T1505.003).
 *
 * Flags script files (php/aspx/asp/jsp/...) created inside web roots
 * (inetpub\wwwroot, htdocs, xampp, phpstudy, ...). A suspicious script
 * basename (cmd, shell, c99, r57, ...) or a non-webserver writer process
 * raises the score; a dedup window suppresses repeated alerts for the
 * same path.
 */
#ifndef EDR_WEBSHELL_DETECTOR_H
#define EDR_WEBSHELL_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class WebshellDetector {
public:
    WebshellDetector(bool enabled, size_t stateCapacity,
                     uint32_t dedupSeconds);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_recentPaths.size(); }

private:
    struct PathState {
        uint64_t lastStamp100ns = 0;
    };

    bool IsScriptExtension(const std::string& extension) const;
    bool IsWebRoot(const std::string& path) const;
    bool IsSuspiciousName(const std::string& name) const;
    bool IsWebServerWriter(const std::string& image) const;
    void WriteState(Event& event, uint32_t score, const std::string& reasons,
                    const std::string& path, const std::string& extension);

    bool m_enabled;
    size_t m_stateCapacity;
    uint64_t m_dedup100ns;
    uint32_t m_dedupSeconds;
    std::unordered_map<std::string, PathState> m_recentPaths;
};

} // namespace edr

#endif /* EDR_WEBSHELL_DETECTOR_H */
