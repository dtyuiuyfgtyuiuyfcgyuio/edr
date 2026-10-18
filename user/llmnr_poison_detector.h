/*
 * llmnr_poison_detector.h - LLMNR/NBT-NS/mDNS poisoning detector
 * (T1557.001).
 *
 * Name-resolution poisoning tools answer LLMNR/NBNS/mDNS queries so that
 * privileged hosts authenticate to the attacker (relayed or cracked
 * afterwards). Two independent planes:
 *
 *   Listener plane (EDR_EVT_NET_LISTENER from collector_listener):
 *     a NON-svchost process binding the name-resolution UDP ports is the
 *     rogue-responder signal:
 *       - UDP 5355 (LLMNR)  -> 85 (the classic AD poisoning port)
 *       - UDP 137  (NBNS)   -> 75
 *       - UDP 5353 (mDNS)   -> 65 (more legitimate third-party noise)
 *     svchost.exe hosting the real responders is normal -> silent;
 *     mDNSResponder.exe (Bonjour) legitimately owns UDP 5353 -> silent.
 *     State-type surface: the same protocol|port repeats inside the dedup
 *     window never re-alert (map with same-key overwrite), only after the
 *     cooldown expires.
 *
 *   Command plane (EDR_EVT_PROCESS_START / EDR_EVT_POWERSHELL_SCRIPT):
 *       - mitm6                                   -> 80 (exclusive here)
 *       - inveigh / responder / nbns_spoof        -> 75
 *     Every command-plane needle matches with full token boundaries
 *     (HasTokenBounded, identical semantics in both this detector and
 *     arp_poison_detector): the START edge requires the string beginning
 *     or a non-alphanumeric character before the stem ("limitm6xx.exe",
 *     vendor "DnsResponder.exe" stay silent); the TAIL edge requires the
 *     end of text or a next character outside [A-Za-z0-9_]. The tail
 *     rejects letter/digit/underscore continuations ("nbns_spoofed",
 *     "nbns-poisoned", "mitm6_domain_scan", "responder -internet") while
 *     accepting the delimiters that really follow a tool token: dot
 *     (path and file suffixes ".exe"/".py"/".psd1"), space, quote, path
 *     separators, hyphen, and end of string.
 *     inveigh and responder overlap forced_auth_detector (T1187) which
 *     scores them 85; the tiers are deliberately staggered because that
 *     detector owns the credential-coercion angle while this one owns the
 *     poisoning angle.
 *
 * Score contract: >=75 MALICIOUS, >=55 SUSPICIOUS, below 55 never stamped.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_LLMNR_POISON_DETECTOR_H
#define EDR_LLMNR_POISON_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class LlmnrPoisonDetector {
public:
    LlmnrPoisonDetector(bool enabled, uint32_t minScore,
                        uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        std::string port;
        std::string tool;
    };

    bool AnalyzeListener(const Event& event, Finding* out) const;
    bool AnalyzeCommandText(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key (signal|port|tool) -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_LLMNR_POISON_DETECTOR_H */
