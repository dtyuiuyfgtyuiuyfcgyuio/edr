/*
 * wifi_cred_theft_detector.h - Non-LSASS credential theft detector
 * (MITRE T1003 / T1555.004 stored credentials).
 *
 * Complements credential_dumping_detector (LSASS/SAM/NTDS plane) with
 * the "cheap" credential stores attackers harvest first:
 *  - netsh wlan export profile key=clear - WiFi profiles with plaintext
 *    pre-shared keys (90)
 *  - netsh wlan export profile without key material (60)
 *  - netsh wlan show profile enumeration bursts (55+)
 *  - vaultcmd /listcreds - Windows credential vault enumeration (75)
 *  - cmdkey /list - saved credential enumeration (55)
 *  - CredentialManager PowerShell module usage (70)
 *  - RDP saved-credential harvesting: cmdkey /list piped to grep/findstr
 *    followed by export (75)
 * Events are stamped with wifi_theft_* fields when confirmed.
 */
#ifndef EDR_WIFI_CRED_THEFT_DETECTOR_H
#define EDR_WIFI_CRED_THEFT_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class WifiCredTheftDetector {
public:
    WifiCredTheftDetector(bool enabled, uint32_t windowSeconds,
                          size_t stateCapacity, uint32_t minRepeatCount);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_keys.size(); }

private:
    struct KeyState {
        bool sawProfileExport = false;
        bool sawKeyClear = false;
        bool sawVaultEnum = false;
        bool sawCmdkeyEnum = false;
        bool sawCredmanModule = false;
        bool sawRdpHarvest = false;
        uint32_t enumCount = 0;
        std::unordered_set<std::string> tools;
        uint64_t lastSeen100ns = 0;
    };

    static bool IsEnumerationCommand(const std::string& image,
                                     const std::string& commandLine,
                                     std::string* outTool);
    static bool IsExportCommand(const std::string& image,
                                const std::string& commandLine,
                                bool* outKeyClear);
    static bool IsVaultCommand(const std::string& image,
                               const std::string& commandLine,
                               std::string* outTool);
    void PurgeExpired(uint64_t now100ns);
    uint32_t ComputeScore(const KeyState& state) const;
    std::string SignalList(const KeyState& state) const;
    std::string ToolList(const KeyState& state) const;
    void WriteState(Event& event, const KeyState& state);

    bool m_enabled;
    uint64_t m_window100ns;
    uint32_t m_windowSeconds;
    size_t m_stateCapacity;
    uint32_t m_minRepeatCount;
    std::unordered_map<std::string, KeyState> m_keys;
};

} // namespace edr

#endif /* EDR_WIFI_CRED_THEFT_DETECTOR_H */
