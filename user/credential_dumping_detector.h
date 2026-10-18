/*
 * credential_dumping_detector.h - Credential dumping detector (MITRE T1003).
 *
 * Correlates multiple credential-theft signals into a single risk score:
 *  - Process access to lsass.exe with read-memory rights (T1003.001)
 *  - Raw SAM/SYSTEM/SECURITY hive file access or reg-save operations
 *    (T1003.002)
 *  - ntds.dit access on domain controllers (T1003.003)
 *  - LSASS/SAM-related named-pipe creation (Mimikatz, nanodump)
 *  - Suspicious DLL load into lsass.exe (e.g. yaotl, kerkberos extensions)
 * Events are stamped with credential_dump_* fields when a confirmed
 * credential-dumping signal is present.
 */
#ifndef EDR_CREDENTIAL_DUMPING_DETECTOR_H
#define EDR_CREDENTIAL_DUMPING_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class CredentialDumpingDetector {
public:
    CredentialDumpingDetector(bool enabled, uint32_t windowSeconds,
                              size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_procs.size(); }

private:
    struct ProcState {
        bool sawLsassAccess = false;
        bool sawSamFile = false;
        bool sawNtdsDit = false;
        bool sawRegSave = false;
        bool sawPipe = false;
        bool sawImageLoad = false;
        uint64_t lastSeen100ns = 0;
    };

    static bool IsLsass(const std::string& image);
    static bool IsSamFile(const std::string& path);
    static bool IsNtdsDit(const std::string& path);
    static bool IsRegSaveKey(const std::string& regKey);
    static bool IsSuspiciousPipe(const std::string& pipeName);
    static bool IsSuspiciousDll(const std::string& dllPath);
    static bool HasReadMemoryAccess(const std::string& accessMask);
    void PurgeExpired(uint64_t now100ns);
    uint32_t PidOf(const Event& event) const;
    uint32_t ComputeScore(const ProcState& state) const;
    std::string SignalList(const ProcState& state) const;
    std::string TechniqueList(const ProcState& state) const;
    void WriteState(Event& event, const ProcState& state,
                    const std::string& detail);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    std::unordered_map<uint32_t, ProcState> m_procs;
};

} // namespace edr

#endif /* EDR_CREDENTIAL_DUMPING_DETECTOR_H */
