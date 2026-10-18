/*
 * archive_staging_detector.h - Archive extraction/staging detector (MITRE T1560.001).
 *
 * Detects adversaries staging payloads via archive utilities:
 *  - Archive tool process starts (7z, winrar, tar, zip, etc.)
 *  - Archive file creation in suspicious locations
 *  - Extraction of files from archives to temp/download directories
 *  - Rapid file creation following archive extraction
 * Events are stamped with archive_staging_* fields when confirmed.
 */
#ifndef EDR_ARCHIVE_STAGING_DETECTOR_H
#define EDR_ARCHIVE_STAGING_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ArchiveStagingDetector {
public:
    ArchiveStagingDetector(bool enabled, uint32_t windowSeconds,
                           size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_procs.size(); }

private:
    struct ProcState {
        bool sawArchiveTool = false;
        bool sawArchiveCreate = false;
        bool sawArchiveRead = false;
        bool sawExtraction = false;
        bool sawTempExtract = false;
        std::unordered_set<std::string> archiveTools;
        std::unordered_set<std::string> archivePaths;
        std::unordered_set<std::string> extractedPaths;
        uint32_t extractedFileCount = 0;
        uint32_t rapidCreateCount = 0;
        uint64_t lastSeen100ns = 0;
    };

    static bool IsArchiveTool(const std::string& image);
    static bool IsArchiveFile(const std::string& path);
    static bool IsArchiveExtension(const std::string& path);
    static bool IsExtractionTool(const std::string& image);
    static bool IsSuspiciousExtractLocation(const std::string& path);
    static bool IsTempOrDownloadPath(const std::string& path);
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const ProcState& state) const;
    std::string SignalList(const ProcState& state) const;
    std::string ToolList(const ProcState& state) const;
    std::string ArchiveList(const ProcState& state) const;
    void WriteState(Event& event, const ProcState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    std::unordered_map<uint32_t, ProcState> m_procs;
};

} // namespace edr

#endif /* EDR_ARCHIVE_STAGING_DETECTOR_H */
