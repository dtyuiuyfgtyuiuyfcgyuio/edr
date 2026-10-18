/*
 * control_panel_proxy_detector.h - Control Panel proxy execution detector
 * (T1218.002).
 *
 * control.exe is a Microsoft-signed binary that loads Control Panel
 * items. It also executes two attacker-relevant file types:
 *
 *   - `control.exe <file>.inf` runs the INF's Install section, giving
 *     code execution from a signed binary and a documented MOTW /
 *     AppLocker-bypass primitive;
 *   - `control.exe <file>.cpl` loads an arbitrary DLL renamed to .cpl
 *     (the CPlApplet entry point is called), which is DLL execution via
 *     a trusted host. The same primitive is reachable through
 *     `rundll32.exe shell32.dll,Control_RunDLL <file>.cpl`.
 *
 * This detector scores the command / script plane that reaches for it:
 *
 *   Command plane (EDR_EVT_PROCESS_START) and PowerShell plane
 *   (EDR_EVT_POWERSHELL_SCRIPT, body ONLY in kScriptBlockText). Text
 *   order: kCommandLine -> (PS_SCRIPT) kScriptBlockText -> kImage.
 *
 * Tiers:
 *   85 control_inf_exec    control.exe plus a `.inf` argument - the INF
 *                          Install section runs. Legitimate
 *                          `control.exe <file>.inf` is rare enough that
 *                          every shape scores.
 *   80 control_cpl_payload control.exe plus a `.cpl` argument that
 *                          resolves into a user-writable or remote
 *                          location (UNC `\\`, or \AppData\ / \Temp\ /
 *                          \Users\Public\ / \ProgramData\ /
 *                          \Downloads\ / \Desktop\). A CPL in one of
 *                          those is a dropped payload, not a system
 *                          applet.
 *   70 control_rundll_cpl  `Control_RunDLL` (or its real shell32
 *                          exports Control_RunDLLA / Control_RunDLLW)
 *                          plus a `.cpl` argument that resolves into
 *                          the same user-writable / remote locations,
 *                          i.e. the rundll32 shell32.dll shape, when
 *                          control.exe itself is not named.
 *
 * Deliberate silences: `control.exe main.cpl` / `control.exe
 * C:\Windows\System32\*.cpl` / `rundll32 shell32.dll,Control_RunDLL
 * main.cpl` (normal applet launch - a bare applet name or a System32
 * path is not a payload), `control.exe /name Microsoft.X`, bare
 * `control.exe`, and `control.exe` with any other extension. The
 * control.exe / Control_RunDLL needles are token-bounded on both edges
 * (HasTokenBounded, same semantics as llmnr_poison_detector /
 * arp_poison_detector): a vendor binary such as "connectwisecontrol.exe"
 * (the 'e' before "control.exe" is alphanumeric) never matches via the
 * start edge, and letter/digit/underscore-glued lookalikes
 * ("control.exed", "Control_RunDLL2", "Control_RunDLL_Legacy") never
 * match via the tail edge. The real shell32 exports Control_RunDLLA /
 * Control_RunDLLW are explicit needles so the tail edge does not drop
 * genuine exports. The `.inf` / `.cpl` extension checks are dot-anchored
 * substring matches (a letter glued before the dot - "xcpl" style -
 * cannot hit them); they are not routed through HasTokenBounded.
 *
 * Coexistence: signed_binary_abuse / indirect_exec own the generic
 * rundll32 and signed-binary proxy faces; this detector owns the
 * T1218.002 Control Panel qualification (control.exe, and the
 * Control_RunDLL CPL shape). The generic rundll32 rules do not key on
 * the CPL extension.
 *
 * Verdict contract: >=75 MALICIOUS, >=55 SUSPICIOUS, below 55 never
 * stamped (the min_score gate runs first; a sub-55 finding early-exits).
 *
 * Dedup: key is the signal (tier) name. The same tier inside the dedup
 * window is suppressed; window expiry or a different tier re-arms.
 * State capacity overflow clears the dedup map (same policy as
 * arp_poison_detector / cloud_metadata_detector).
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_CONTROL_PANEL_PROXY_DETECTOR_H
#define EDR_CONTROL_PANEL_PROXY_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ControlPanelProxyDetector {
public:
    ControlPanelProxyDetector(bool enabled, uint32_t minScore,
                              uint32_t dedupWindowSeconds,
                              size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        std::string indicator;
    };

    bool AnalyzeCommandText(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key (signal) -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_CONTROL_PANEL_PROXY_DETECTOR_H */
