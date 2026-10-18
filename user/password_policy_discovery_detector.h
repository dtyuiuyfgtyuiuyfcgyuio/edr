/*
 * password_policy_discovery_detector.h - Password policy discovery
 * detector (T1201).
 *
 * Before spraying or cracking, an operator reads the domain / local
 * password and lockout policy: the lockout threshold decides how many
 * attempts per account are safe, and the minimum length decides the
 * cracking budget. This detector scores the command / script plane that
 * performs that read:
 *
 *   Command plane (EDR_EVT_PROCESS_START) and PowerShell plane
 *   (EDR_EVT_POWERSHELL_SCRIPT, body ONLY in kScriptBlockText). Text
 *   order: kCommandLine -> (PS_SCRIPT) kScriptBlockText -> kImage.
 *
 * Tiers:
 *   75 domain_password_policy_query the AD policy cmdlets that exist only
 *                                   to read the policy:
 *                                   Get-ADDefaultDomainPasswordPolicy /
 *                                   Get-ADFineGrainedPasswordPolicy /
 *                                   Get-ADUserResultantPasswordPolicy /
 *                                   Get-DomainPolicy (PowerView).
 *   70 net_accounts_domain_read      `net accounts /domain` - the
 *                                   built-in domain policy read.
 *   65 net_accounts_read             bare `net accounts` - the built-in
 *                                   local policy read.
 *   65 secedit_policy_export         `secedit /export` - dumps the local
 *                                   security policy (password and
 *                                   lockout settings included) to a file.
 *
 * Deliberate silences - this detector owns the DISCOVERY face only:
 *   - `net accounts` carrying any setter flag (/minpwlen, /maxpwage,
 *     /minpwage, /uniquepw, /lockoutthreshold, /lockoutduration,
 *     /lockoutwindow, /forcelogoff) is a policy MODIFICATION, owned by
 *     AccountOpDetector (account_policy_change), and stays silent here;
 *   - `secedit` without /export (e.g. /configure) is a policy write and
 *     stays silent;
 *   - `net accounts` mentions inside other verbs never match (the
 *     token-bounded "net accounts" needle, HasTokenBounded - same
 *     semantics as llmnr_poison_detector / arp_poison_detector:
 *     "tenet accounts" fails the start edge, "net accountsx" /
 *     "net1 accounts_audit" the tail edge).
 *
 * Verdict contract: >=75 MALICIOUS, >=55 SUSPICIOUS, below 55 never
 * stamped (the min_score gate runs first; a sub-55 finding early-exits).
 *
 * Dedup: key is the signal (tier) name. The same tier inside the dedup
 * window is suppressed; window expiry or a different tier re-arms.
 * State capacity overflow clears the dedup map (same policy as
 * netprovider_persist_detector).
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_PASSWORD_POLICY_DISCOVERY_DETECTOR_H
#define EDR_PASSWORD_POLICY_DISCOVERY_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PasswordPolicyDiscoveryDetector {
public:
    PasswordPolicyDiscoveryDetector(bool enabled, uint32_t minScore,
                                    uint32_t dedupWindowSeconds,
                                    size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        std::string tool;
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

#endif /* EDR_PASSWORD_POLICY_DISCOVERY_DETECTOR_H */
