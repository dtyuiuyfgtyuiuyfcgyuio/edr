/*
 * local_collect_detector.h - Local bulk collection / staging detector (MITRE T1005).
 *
 * COVERS (in scope - Collection, TA0009):
 *   - Recursive enumeration of user profile directories (Desktop / Documents /
 *     Downloads / OneDrive / AppData) accompanied by a copy action.
 *   - Compress-Archive / archive tool *packaging* of a user profile directory
 *     (the opposite direction of archive_staging's extraction detection).
 *   - Copying / moving user-profile files into a local staging directory
 *     (%TEMP% / ProgramData / Public / AppData\Local\Temp / AppData\Roaming\Temp).
 *   - A single process performing a short-window burst of FILE_READ events whose
 *     basename matches a document extension, followed by a same-name / same-class
 *     file appearing in a staging directory.
 *
 * DOES NOT COVER (owned by other detectors; this module must NOT duplicate):
 *   - Archive tool UNPACKING / extraction landing -> archive_staging (T1560.001)
 *   - Credential / key file hunting              -> cred_file_hunt / reg_cred_hunt
 *   - Outbound network exfiltration             -> data_exfiltration (T1041) / web_exfil
 *   - Browser credential-store theft            -> browser_theft
 *   - USB copy exfiltration                     -> usb_exfil
 *   - Honeypot / canary lure trips              -> canary
 *
 * Scoring model (house thresholds, see ComputeScore in the .cpp):
 *   >= 75            -> write score + verdict "malicious" + signals + techniques
 *   55 .. 74         -> write score + verdict "suspicious" + signals + techniques
 *   < 55 (or < cfg minScore) -> write NOTHING (fully silent)
 * Only FILE_CREATE / FILE_READ / PROCESS_START are inspected.
 *
 * Thread-safety: no internal locking; only the single EventBus consumer thread
 * calls Enrich (see main.cpp).
 */
#ifndef EDR_LOCAL_COLLECT_DETECTOR_H
#define EDR_LOCAL_COLLECT_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class LocalCollectDetector {
public:
    LocalCollectDetector(bool enabled, uint32_t minScore,
                         uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_procs.size(); }

private:
    struct ProcState {
        bool sawEnumProfile = false;     /* recursive enumeration of a profile dir */
        bool sawArchiveProfile = false;  /* archiver packing a profile dir */
        bool sawStageCopy = false;       /* doc-class file created in a staging dir */
        bool sawStageLanding = false;    /* staging file basename matched a read doc */
        uint32_t docReadCount = 0;       /* FILE_READ hits on document extensions */
        std::unordered_set<std::string> readDocNames; /* basenames of read docs */
        uint64_t lastSeen100ns = 0;
        uint64_t lastStamp100ns = 0;
    };

    static bool IsDocumentExtension(const std::string& lowerBase);
    static bool IsProfilePath(const std::string& lower);
    static bool IsStagingPath(const std::string& lower);
    static bool IsProfileEnumeration(const std::string& lowerImage,
                                     const std::string& lowerText);
    static bool IsArchivePackaging(const std::string& lowerImage,
                                   const std::string& lowerText);
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const ProcState& state) const;
    std::string SignalList(const ProcState& state) const;
    std::string TechniqueList(const ProcState& state) const;
    void WriteState(Event& event, const ProcState& state);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;
    std::unordered_map<uint32_t, ProcState> m_procs;

    /* Correlation ("episode") window for per-process collection state.
     * Deliberately distinct from m_dedupWindow100ns: the dedup window only
     * suppresses re-stamping of an already-alerted process, it must NOT
     * drive state expiry. Conflating the two made dedup_window_seconds=0
     * (documented as "dedup disabled") wipe the state on every event, so a
     * multi-file collection burst could never accumulate. Hardcoded per the
     * batch contract (extra thresholds are constants, not config keys). */
    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
    static constexpr uint64_t kEpisodeWindow100ns = 900ULL * kFiletimeTicksPerSecond;
};

} // namespace edr

#endif /* EDR_LOCAL_COLLECT_DETECTOR_H */
