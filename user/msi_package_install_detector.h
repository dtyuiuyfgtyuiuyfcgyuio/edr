/*
 * msi_package_install_detector.h - MSI package install abuse detector
 * (T1546.016).
 *
 * msiexec.exe is a Microsoft-signed binary that installs MSI packages.
 * Because it is signed and trusted, attackers use it to execute a
 * package they dropped or fetched: `msiexec /i <url>` pulls the MSI
 * straight from the internet, and `msiexec /i %TEMP%\x.msi` runs a
 * staged payload. The installed package's custom actions then run with
 * the privileges msiexec was launched with - signed-binary proxy
 * execution (T1218 territory) reached through an installer package
 * (T1546.016).
 *
 * This detector scores the command / script plane:
 *
 *   Command plane (EDR_EVT_PROCESS_START) and PowerShell plane
 *   (EDR_EVT_POWERSHELL_SCRIPT, body ONLY in kScriptBlockText). Text
 *   order: kCommandLine -> (PS_SCRIPT) kScriptBlockText -> kImage.
 *
 * Tiers (an install verb - `/i`, `/package`, `/a`, including the quoted
 * PowerShell shape `-ArgumentList '/i','<url>'` - must be present):
 *   85 msi_remote_install  the package comes from a URL (http / https /
 *                          ftp) or a UNC share - fetched straight from
 *                          attacker infrastructure.
 *   70 msi_staged_install  the package resolves into a user-writable
 *                          location (\AppData\, \Temp\, \Users\Public\,
 *                          \ProgramData\, \Downloads\, \Desktop\) - a
 *                          dropped file rather than a deployed product.
 *
 * Deliberate silences: a package under Program Files or any other
 * non-user-writable path is a normal deployment and stays silent, as do
 * msiexec invocations without an install verb (`/x` uninstall, `/p`
 * patch, `/unreg`, bare `msiexec`). `msiexec` need not be the image:
 * the needle is token-bounded on both edges in the text (HasTokenBounded,
 * same semantics as llmnr_poison_detector / arp_poison_detector), so
 * "my msiexec.exe" and `cmd /c msiexec ...` both match while
 * "xmsiexec.exe" (start edge) and letter/underscore-glued lookalikes
 * such as "msiexecd" / "msiexec_silent" (tail edge) do not.
 *
 * Coexistence: lolbin_parent_child / lolbin_chain own the generic
 * "known LOLBin spawned / chained" faces; this detector owns the
 * T1546.016 installer-package qualification (msiexec + install verb +
 * remote or staged package).
 *
 * Verdict contract: >=75 MALICIOUS, >=55 SUSPICIOUS, below 55 never
 * stamped (the min_score gate runs first; a sub-55 finding early-exits).
 *
 * Dedup: key is "signal|package" where package is the `.msi` token found
 * in the text when one is present (otherwise the signal alone). Two
 * different packages alert twice; re-installing the same one inside the
 * window is suppressed. State capacity overflow clears the dedup map
 * (same policy as netprovider_persist_detector).
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_MSI_PACKAGE_INSTALL_DETECTOR_H
#define EDR_MSI_PACKAGE_INSTALL_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class MsiPackageInstallDetector {
public:
    MsiPackageInstallDetector(bool enabled, uint32_t minScore,
                              uint32_t dedupWindowSeconds,
                              size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        std::string package;
        std::string source;
    };

    bool AnalyzeCommandText(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key (signal|package) -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_MSI_PACKAGE_INSTALL_DETECTOR_H */
