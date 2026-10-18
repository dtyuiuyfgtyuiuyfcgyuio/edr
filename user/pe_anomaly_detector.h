/*
 * pe_anomaly_detector.h - Static PE anomaly detector.
 *
 * Consumes FILE_CREATE / FILE_RENAME / FILE_INTEGRITY events whose file
 * path carries a PE extension (.exe/.dll/.scr/.ocx/.cpl/.sys), reads the
 * file from disk (bounded by max_file_bytes) and runs the pure
 * ScanPeBuffer parser (pe_anomaly_scan.h) to score static anomalies
 * (packer sections, RWX sections, virtual-only sections, high-entropy
 * executable data, timestamp anomalies, overlay).
 *
 * The event sources are naturally bounded: FILE_CREATE arrives for the
 * file-fallback watched directories (default %TEMP% and
 * \Users\Public\Downloads), FILE_INTEGRITY only for configured FIM files,
 * so an empty scan_dirs filter does not imply unbounded scanning. When
 * scan_dirs is configured, only paths under one of the directories are
 * read. Unreadable / non-PE files stay silent.
 */
#ifndef EDR_PE_ANOMALY_DETECTOR_H
#define EDR_PE_ANOMALY_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PeAnomalyDetector {
public:
    PeAnomalyDetector(bool enabled, uint32_t minScore,
                      uint32_t dedupWindowSeconds, size_t stateCapacity,
                      uint64_t maxFileBytes,
                      std::vector<std::string> scanDirs);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

private:
    struct Finding {
        uint32_t score = 0;
        std::string signals;
        std::string sections;
    };
    bool ShouldScanPath(const std::string& lowerPath) const;
    bool ReadFileBytes(const std::string& utf8Path,
                       std::vector<uint8_t>* buffer) const;
    void Stamp(Event& event, const Finding& finding, const std::string& key);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;
    uint64_t m_maxFileBytes;
    std::vector<std::string> m_scanDirs; /* lowered, backslash-normalized */
    std::unordered_map<std::string, uint64_t> m_lastAlert;
    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_PE_ANOMALY_DETECTOR_H */
