/*
 * hidden_artifacts_detector.h - Hidden artifacts detector
 * (MITRE T1564.004 alternate data streams / T1564.001 hidden files).
 *
 * Detects adversaries hiding payloads from casual inspection:
 *  - Alternate data stream creation: command-line redirection or file
 *    operations targeting "file:stream" / ":$DATA" paths (85)
 *  - ADS payloads staged from interpreters (PowerShell / certutil /
 *    bitsadmin) rather than plain shell echo (90)
 *  - Hidden attribute set via attrib +h / +s on user-writable paths (70)
 *  - Hidden attribute set on executable/script files (85)
 *  - PowerShell attribute flip: Set-ItemProperty -Name Attributes
 *    -Value Hidden or [IO.File]::SetAttributes Hidden (75)
 *  - Create-then-hide correlation: a process creates a file and hides
 *    it within the same window (80)
 * Events are stamped with hidden_artifacts_* fields when confirmed.
 */
#ifndef EDR_HIDDEN_ARTIFACTS_DETECTOR_H
#define EDR_HIDDEN_ARTIFACTS_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class HiddenArtifactsDetector {
public:
    HiddenArtifactsDetector(bool enabled, uint32_t windowSeconds,
                            size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_procs.size(); }

private:
    struct ProcState {
        std::unordered_set<std::string> createdFiles;
        std::unordered_set<std::string> hiddenPaths;
        std::unordered_set<std::string> adsPaths;
        bool sawHiddenAttrib = false;
        bool sawAdsWrite = false;
        bool sawInterpreterAds = false;
        uint64_t lastSeen100ns = 0;
    };

    static bool IsInterpreter(const std::string& image);
    static bool IsExecutablePath(const std::string& path);
    static bool IsUserWritablePath(const std::string& path);
    static std::string AdsPathInCommandLine(const std::string& commandLine);
    static std::string AdsPathInFilePath(const std::string& filePath);
    static bool IsHiddenAttribCommand(const std::string& commandLine,
                                      std::string* outPath);
    static bool IsPowerShellHiddenAttribute(const std::string& commandLine,
                                            std::string* outPath);
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const ProcState& state) const;
    std::string SignalList(const ProcState& state) const;
    std::string PathList(const std::unordered_set<std::string>& paths) const;
    void WriteState(Event& event, const ProcState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    std::unordered_map<uint32_t, ProcState> m_procs;
};

} // namespace edr

#endif /* EDR_HIDDEN_ARTIFACTS_DETECTOR_H */
