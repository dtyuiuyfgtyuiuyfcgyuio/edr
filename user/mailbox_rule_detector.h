/*
 * mailbox_rule_detector.h - Mailbox rule forwarding detector (T1114.003).
 *
 * Adversaries with a compromised Exchange/OWA session create inbox rules
 * that silently forward (or forward-as-attachment) every incoming mail to
 * an external drop mailbox. This detector scores the Exchange management
 * surface on both planes:
 *
 *   PowerShell plane (EDR_EVT_POWERSHELL_SCRIPT, body only in
 *   kScriptBlockText):
 *     - New-InboxRule / Set-InboxRule with -ForwardTo / -RedirectTo /
 *       -ForwardAsAttachmentTo                    -> 90 (external forward)
 *     - Set-Mailbox with -ForwardingSmtpAddress /
 *       -ForwardingAddress / -DeliverToMailboxAndForward -> 85
 *     - the same cmdlets WITHOUT forwarding parameters (view / rename /
 *       display-name maintenance) are legitimate admin work -> silent
 *
 *   Command plane (EDR_EVT_PROCESS_START kCommandLine):
 *     - New-InboxRule / Set-InboxRule with a forwarding parameter -> 90
 *     - the bare cmdlet carried on a raw command line
 *       (powershell.exe -Command "New-InboxRule ...")              -> 60
 *       SUSPICIOUS telemetry for tuning.
 *
 * Score contract: >=75 MALICIOUS, >=55 SUSPICIOUS, below 55 never stamped
 * (no verdict field). Alerts dedup per signal|target key inside the dedup
 * window; a different forwarding target re-arms immediately.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_MAILBOX_RULE_DETECTOR_H
#define EDR_MAILBOX_RULE_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class MailboxRuleDetector {
public:
    MailboxRuleDetector(bool enabled, uint32_t minScore,
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

    /* `fromCommandLine` is true when the text came from a PROCESS_START
     * kCommandLine; the bare-cmdlet middle tier only fires there. */
    bool Analyze(const std::string& lower, bool fromCommandLine,
                 Finding* out) const;
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

#endif /* EDR_MAILBOX_RULE_DETECTOR_H */
