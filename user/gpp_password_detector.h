/*
 * gpp_password_detector.h - Group Policy Preferences credential theft
 * detector (T1552.006).
 *
 * Group Policy Preferences let an administrator embed a password in a
 * GPP XML file (Groups.xml / Services.xml / ScheduledTasks.xml / ...)
 * under SYSVOL. Microsoft published the AES key, so the `cpassword`
 * attribute is trivially decryptable - the "GPP password" is a standing
 * cleartext-adjacent credential in every domain. This detector scores
 * the command / script plane that reaches for it:
 *
 *   Command plane (EDR_EVT_PROCESS_START) and PowerShell plane
 *   (EDR_EVT_POWERSHELL_SCRIPT, body ONLY in kScriptBlockText). Text
 *   order: kCommandLine -> (PS_SCRIPT) kScriptBlockText -> kImage.
 *
 * Tiers:
 *   90 gpp_password_tool  the ready-made extraction cmdlets:
 *                         Get-GPPPassword / Get-GPPAutologon /
 *                         Get-GPPDomainPassword / Get-CachedGPPPassword.
 *                         One invocation enumerates SYSVOL and prints the
 *                         decrypted passwords - the whole theft chain.
 *   85 gpp_decrypt_tool   standalone GPP decryptors: gpp-decrypt,
 *                         gpprefdecrypt(.py), GPPrefDecrypt.exe.
 *   80 cpassword_search   a `cpassword` token (token-bounded on both
 *                         edges: "encpassword" / "mypassword" stay
 *                         silent via the start edge, "cpassworded" /
 *                         "cpassword_dump" via the tail edge) combined
 *                         with a search verb (findstr /
 *                         Select-String / grep / find / type) - the
 *                         manual "grep SYSVOL for cpassword" hunt.
 *   75 gpp_xml_access     a SYSVOL path plus one of the GPP XML names
 *                         (Groups.xml / Services.xml / ScheduledTasks.xml
 *                         / Printers.xml / Drives.xml / DataSources.xml /
 *                         Registry.xml) - reading the policy file that
 *                         carries the embedded credential.
 *   65 cpassword_reference a bare token-bounded `cpassword` token in a
 *                         script body (a parser that never names a
 *                         tool); observation tier for tuning.
 *
 * Coexistence with GpoAbuseDetector (T1484.001): that detector owns
 * *writing* policy (registry.pol / gpt.ini staged into SYSVOL, New-GPO,
 * lgpo.exe) and explicitly leaves read-only gpresult / Get-GPO silent.
 * This detector owns the *read* face that turns a GPP file into a
 * credential, so the two do not overlap.
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
#ifndef EDR_GPP_PASSWORD_DETECTOR_H
#define EDR_GPP_PASSWORD_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class GppPasswordDetector {
public:
    GppPasswordDetector(bool enabled, uint32_t minScore,
                        uint32_t dedupWindowSeconds, size_t stateCapacity);

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

#endif /* EDR_GPP_PASSWORD_DETECTOR_H */
