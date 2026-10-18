/*
 * arp_poison_detector.h - ARP cache poisoning detector (T1557.002).
 *
 * ARP poisoning tools corrupt the IPv4 neighbor cache so that traffic to
 * a victim host (typically the default gateway) is redirected through
 * the attacker - a MITM position whose traffic is then relayed or
 * sniffed. One command/script plane with two score tiers:
 *
 *   Command plane (EDR_EVT_PROCESS_START) and PowerShell plane
 *   (EDR_EVT_POWERSHELL_SCRIPT, body ONLY in kScriptBlockText). Text
 *   order: kCommandLine -> (PS_SCRIPT) kScriptBlockText -> kImage.
 *
 * Tiers:
 *   80 arp_poison_tool       dedicated ARP poisoner binaries on the
 *                            command/script text: ettercap / bettercap /
 *                            arpspoof, including .exe/.py suffixed
 *                            shapes and any path-separator, quote or
 *                            whitespace prefix. EVERY needle goes
 *                            through HasTokenBounded (same helper
 *                            semantics as llmnr_poison_detector.cpp):
 *                            full token boundaries on BOTH edges. The
 *                            START edge (string beginning or a
 *                            non-alphanumeric character before the
 *                            stem) keeps letter-prefixed lookalikes
 *                            ("xettercap", "myarpspoof") silent and is
 *                            also what keeps the "ettercap" needle from
 *                            firing INSIDE "bettercap" - tool
 *                            attribution stays correct. The TAIL edge
 *                            (end of text or a next character outside
 *                            [A-Za-z0-9_]) keeps letter/digit/underscore
 *                            continuations ("ettercapped",
 *                            "bettercapped", "arpspoofing") silent,
 *                            while accepting dot (".exe"/".py" file
 *                            suffixes), space, quote, path separators,
 *                            hyphen and end of string as tail
 *                            delimiters.
 *   75 arp_static_table_load `arp -f` / `arp -F` (case-insensitive, also
 *                            the `arp.exe -f` and quoted
 *                            `"C:\...\arp.exe" -f` shapes): loading a
 *                            static ARP entry file is the standard
 *                            poisoning pre-positioning move. Other arp
 *                            verbs (`arp -a` / `-d` / `-g`), bare `arp`
 *                            and `getmac` are normal operations and stay
 *                            silent, as are letter-glued shapes
 *                            ("sharp.exe -f", "arpfile" on the start
 *                            edge) and letter-continued flags ("arp
 *                            -fl", "arp -file" on the tail edge - the
 *                            flag token must end right after the "f").
 *   There is deliberately NO "bare tool name without arguments" tier:
 *   the binary name alone already fires the 80 tier, and a lower
 *   implicit tier would only re-alert the same event.
 *
 * Verdict contract: >=75 MALICIOUS, >=55 SUSPICIOUS, below 55 never
 * stamped (the min_score gate runs first; a sub-55 finding early-exits).
 *
 * Dedup: key is "signal|tool" for the tool tier ("arp_poison_tool|ettercap"
 * / "...|bettercap" / "...|arpspoof") and plain "signal" for the
 * static-load tier (every arp -f/-F/.exe/quoted spelling shares one key).
 * The same key inside the dedup window is suppressed; window expiry or a
 * different key re-arms. State capacity overflow clears the dedup map
 * (same policy as llmnr_poison_detector).
 *
 * Coexistence with NetworkSniffingDetector (EDR-378, T1040): that
 * detector already scores ettercap/bettercap at 80 on the sniffing face
 * ("packet capture tool invoked") using PLAIN substring matching. This
 * detector owns the ARP-poisoning qualification (T1557.002) and fills the
 * faces EDR-378 leaves open: arpspoof (absent from its capture-tool
 * list) and static ARP table loading. The tiers are deliberately
 * staggered from EDR-378's 80 in three ways:
 *   - arpspoof and arp -f/-F fire here ONLY (single high face);
 *   - ettercap/bettercap stamp BOTH scores by design - EDR-378 carries
 *     the T1040 capture angle, this detector the T1557.002 poisoning
 *     angle (same accepted cross-technique pattern as inveigh:
 *     forced_auth T1187 85 + llmnr_poison T1557.001 75); the fields and
 *     rule families are disjoint so no band collides;
 *   - matching semantics are tighter here: token-bounded needles (start
 *     AND tail edges) keep lookalike words that EDR-378's unbounded
 *     substring scores on the T1040 face silent on this one -
 *     letter-prefixed ("xettercap") via the start edge and
 *     letter-continued ("ettercapped") via the tail edge.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_ARP_POISON_DETECTOR_H
#define EDR_ARP_POISON_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class ArpPoisonDetector {
public:
    ArpPoisonDetector(bool enabled, uint32_t minScore,
                      uint32_t dedupWindowSeconds, size_t stateCapacity);

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

    /* dedup key (signal|tool, or plain signal for the static-load tier)
     * -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_ARP_POISON_DETECTOR_H */
