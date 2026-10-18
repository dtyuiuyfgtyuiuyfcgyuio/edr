/*
 * software_discovery_detector.h - Per-actor software discovery breadth
 * detector (T1518 Software Discovery / T1518.001 Security Software
 * Discovery).
 *
 * Classifies lowered command lines / PowerShell script bodies into what kind
 * of software census one actor is taking:
 *
 *   software_inventory  - wmic product get [name] / Get-Package [-ProviderName]
 *                         / Get-WmiObject Win32_Product /
 *                         Get-CimInstance Win32_Product / Get-InstalledSoftware
 *                         / "software inventory". Win32_Product is the classic
 *                         inventory enumerator and is expensive enough to
 *                         fingerprint a probe.
 *   security_products   - wmic /namespace:\\root\securitycenter2 product /
 *                         Get-CimInstance -Namespace root\securitycenter2 /
 *                         Get-MpComputerStatus / Get-MpPreference /
 *                         Get-CimInstance -Namespace root/.../Defender /
 *                         sc query WinDefend|MpsSvc / "securitycenter2" /
 *                         Get-Service -Name WinDefend / third-party AV
 *                         uninstall-string enumeration (avast, kaspersky,
 *                         mcafee, symantec, eset, sophos, trend micro,
 *                         norton, bitdefender).                          (T1518.001)
 *   installed_apps      - HKLM:\Software\Microsoft\Windows\CurrentVersion\
 *                         Uninstall (Get-ItemProperty / Get-ChildItem) /
 *                         "installed programs" / dir "%ProgramFiles%" /
 *                         dir "%ProgramFiles(x86)%" / dir "%AppData%" /
 *                         Get-ChildItem env:ProgramFiles.
 *
 * Fires only on breadth or privilege: a lone `wmic product get` is routine
 * administration and stays silent. An actor (image basename + owning user)
 * that touches at least m_minCategories distinct categories inside the rolling
 * window is stamped with software_discovery_score /
 * software_discovery_verdict / software_discovery_signals /
 * software_discovery_categories / software_discovery_category_count. A
 * privileged actor enumerating security products is escalated regardless of
 * how few categories it had to touch.
 *
 * Complements HostProfileDetector (T1007/T1012/T1016/T1018/T1069/T1082/T1087,
 * which has no software-inventory category and never looks at AV products)
 * and DiscoveryReconDetector (host-wide buckets whose internal
 * security_software_discovery category emits no ATT&CK id). This detector
 * supplies the T1518 / T1518.001 mapping and keys on the *actor* rather than
 * on the host.
 *
 * House contract: PROCESS_START carries kCommandLine; POWERSHELL_SCRIPT
 * carries kScriptBlockText only. Text is read kCommandLine, then
 * kScriptBlockText for script events, then kImage as fallback.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_SOFTWARE_DISCOVERY_DETECTOR_H
#define EDR_SOFTWARE_DISCOVERY_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class SoftwareDiscoveryDetector {
public:
    SoftwareDiscoveryDetector(bool enabled, uint32_t minScore,
                              uint32_t windowSeconds, uint32_t minCategories,
                              uint32_t dedupWindowSeconds,
                              size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_actors.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        uint32_t categoryCount = 0;
        std::string categories; /* sorted, comma-joined */
        bool privileged = false;
        bool securityProducts = false;
        const char* signal = "";
    };

    /* Classify lowered command line / script text into every software-
     * discovery category it asks about. One command may span several
     * (an inventory sweep that also reads the AV uninstall strings), so the
     * result is a set; empty means the text asks no software question. */
    bool Classify(const std::string& lower,
                  std::unordered_set<std::string>* categories) const;

    bool Analyze(Event& event, Finding* out);
    void Stamp(Event& event, const Finding& finding) const;
    void PurgeExpired(uint64_t now100ns);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_window100ns;
    uint32_t m_minCategories;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    struct ActorState {
        /* category -> last seen ts100ns inside the rolling window */
        std::unordered_map<std::string, uint64_t> categories;
        uint64_t lastSeen100ns = 0;
        uint64_t lastStamp100ns = 0;
        uint32_t lastFlaggedCount = 0;
        bool privileged = false;
    };
    std::unordered_map<std::string, ActorState> m_actors;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_SOFTWARE_DISCOVERY_DETECTOR_H */