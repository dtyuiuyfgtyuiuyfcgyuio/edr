/*
 * mailbox_delegate_detector.h - Mailbox delegate permission grant detector
 * (T1098.002 Additional Email Delegate Permissions).
 *
 * Delegating another user's mailbox (full access, send-as, send-on-behalf,
 * folder permissions) to an account that did not hold it is a core BEC
 * action: the attacker reads the victim's mail and speaks as the victim
 * without ever touching their password. This detector scores the Exchange
 * management surface on both planes:
 *
 *   PowerShell plane (EDR_EVT_POWERSHELL_SCRIPT, body only in
 *   kScriptBlockText) and command plane (EDR_EVT_PROCESS_START; text
 *   acquisition kCommandLine -> kImage fallback, which covers the
 *   `powershell.exe -Command "Add-MailboxPermission ..."` carrier):
 *
 *     85 delegate_full_access_grant
 *        Add-MailboxPermission / Add-ADPermission with -AccessRights
 *        (or the -Accessright spelling) whose value contains FullAccess
 *        (case-insensitive; -User / -Identity may appear in any order)
 *     80 delegate_send_as_grant
 *        Add-RecipientPermission with -AccessRights ... SendAs, or
 *        Set-Mailbox with -GrantSendOnBehalfTo, or Add-ADPermission with
 *        -ExtendedRights ... Send-as / "Send As" (all three shapes are
 *        merged into one signal: they hand out the right to speak as the
 *        victim, differing only in cmdlet surface)
 *     65 delegate_folder_permission_grant
 *        Add-MailboxFolderPermission regardless of sub-parameters
 *
 *   Flag values are bound to the owning grant cmdlet's span: the flags
 *   are only searched between a grant cmdlet occurrence and the next
 *   mailbox-delegation cmdlet token, so multi-statement blocks never
 *   take a value across statements (a later Remove-* statement carrying
 *   -AccessRights FullAccess cannot endorse an earlier Add-*).
 *   PowerShell backtick line continuations (` + newline + indent)
 *   inside a flag value are treated as soft whitespace.
 *
 *   Silent surface (governance / non-grant semantics, no score ever):
 *     - Get-*Mailbox*Permission* / Get-RecipientPermission /
 *       Get-ADPermission queries (no add-/set- grant cmdlet matched)
 *     - Remove-MailboxPermission / Remove-RecipientPermission: removing a
 *       delegate is remediation, not a grant (even when the command text
 *       carries -AccessRights FullAccess/SendAs)
 *     - -AccessRights values with no grant semantics (ReadPermission,
 *       ChangeOwner, CreateItems ...): only grant-semantic values score
 *     - a bare Set-Mailbox without -GrantSendOnBehalfTo (quota / name
 *       maintenance)
 *     - Set-MailboxFolderPermission: not an Add-* grant cmdlet; the
 *       set-mailbox needle is boundary-checked so it can never be
 *       mistaken for Set-Mailbox
 *
 * Score contract: >=75 MALICIOUS, >=55 SUSPICIOUS, below 55 never stamped
 * (the detector's lowest tier is 65, but the sub-verdict guard is kept as
 * the house contract). Alerts dedup per signal|target key inside the dedup
 * window; the target is the delegated mailbox's -Identity (the full
 * "-identity" needle is used so a neighbouring "-Id <n>" parameter can
 * never be mistaken for the identity). Identity-free commands dedup on the
 * empty target; a different identity re-arms immediately.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_MAILBOX_DELEGATE_DETECTOR_H
#define EDR_MAILBOX_DELEGATE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class MailboxDelegateDetector {
public:
    MailboxDelegateDetector(bool enabled, uint32_t minScore,
                            uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        const char* cmdlet = "";
        std::string target;
    };

    bool Analyze(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key (signal|target) -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_MAILBOX_DELEGATE_DETECTOR_H */
