/*
 * bits_abuse_detector.h - BITS job abuse detector (MITRE T1197).
 *
 * Detects adversaries abusing the Background Intelligent Transfer Service
 * for malware delivery and exfiltration ("LOLBITS"):
 *  - bitsadmin.exe / PowerShell Start-BitsTransfer launches
 *  - Download jobs pulling from remote URLs (http/https/UNC)
 *  - Downloads landing on executable/script paths or transient directories
 *  - File creations attributed to the BITS tool itself
 * Events are stamped with bits_abuse_* fields when confirmed.
 */
#ifndef EDR_BITS_ABUSE_DETECTOR_H
#define EDR_BITS_ABUSE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class BitsAbuseDetector {
public:
    BitsAbuseDetector(bool enabled, uint32_t windowSeconds,
                      size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_procs.size(); }

private:
    struct ProcState {
        bool sawBitsTool = false;
        bool sawDownloadJob = false;
        bool sawUploadJob = false;
        bool sawRemoteUrl = false;
        bool sawExecTarget = false;
        std::unordered_set<std::string> tools;
        std::unordered_set<std::string> urls;
        std::unordered_set<std::string> targets;
        uint64_t lastSeen100ns = 0;
    };

    static bool IsBitsTool(const std::string& image);
    static bool IsExecutablePath(const std::string& path);
    static bool IsTransientPath(const std::string& path);
    static bool LooksLikeUrl(const std::string& value);
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const ProcState& state) const;
    std::string SignalList(const ProcState& state) const;
    std::string ToolList(const ProcState& state) const;
    std::string UrlList(const ProcState& state) const;
    std::string TargetList(const ProcState& state) const;
    void WriteState(Event& event, const ProcState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    std::unordered_map<uint32_t, ProcState> m_procs;
};

} // namespace edr

#endif /* EDR_BITS_ABUSE_DETECTOR_H */
