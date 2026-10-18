/*
 * password_vault_detector.h - Password manager vault access detector
 * (T1555.005).
 *
 * Complements cred_file_hunt_detector (which owns the generic 65-75
 * "vault file referenced" tiers) by focusing on the tool / execution
 * surface that bulk-extracts or stages vault contents:
 *
 *   - keepass2john                        -> 90 (hash extraction for
 *         offline cracking: the full theft chain in one invocation)
 *   - bw export (Bitwarden CLI)           -> 85
 *   - .kdbx/.kdb database staged with an export/copy/archive verb
 *                                         -> 80
 *   - keepassxc-cli export subcommand     -> 70 (subcommand-level
 *         judgment, see "keepassxc export judgment" below)
 *   - keepassxc-cli automation use        -> 60
 *   - 1Password CLI bulk reads
 *     (op item list / op read / op://)    -> 60
 *
 * A bare "keepass" mention or a plain .kdbx reference without a staging
 * verb stays silent here - cred_file_hunt_detector owns that baseline
 * signal (65-75). The GUI keepassxc process stays silent too unless an
 * export subcommand directly follows the keepassxc/keepassxc.exe token
 * (then 70, same as the CLI form).
 *
 * keepassxc export judgment (subcommand level - NOT "export anywhere in
 * the text"; prose words must not upgrade the 60 automation tier). The
 * 70 tier fires only when an export token is directly bound to a
 * keepassxc executable token (keepassxc / keepassxc-cli / keepassxc.exe
 * / keepassxc-cli.exe, matched as one word-bounded token):
 *
 *   1. Direct subcommand: scanning forward from the executable token,
 *      skipping an attached ".exe", whitespace/quotes and '-'-prefixed
 *      option tokens (the "keepassxc-cli [options] <command>" usage
 *      shape, so "-q export" and "-k <keyfile> export" reach the
 *      command slot), the first two non-option tokens are inspected;
 *      either being exactly "export" upgrades to 70. The scan stops at
 *      '#' (cmd/PowerShell comment tail - nothing after it executes).
 *   2. Hyphenated compound (deliberate retention): a word-boundary
 *      complete "export" after the first executable token belonging to
 *      a hyphenated compound - immediately followed by '-' as in
 *      "keepassxc-cli show db | export-csv out" (piped export tool =
 *      real external transfer) or immediately preceded by '-' as in
 *      "icon-export". Bare prose words ("export docs", "exported",
 *      "exports") never qualify and stay at 60.
 *
 * Pinned cases: "keepassxc-cli export db.kdbx out.csv" -> 70;
 * "keepassxc export ..." -> 70; "keepassxc-cli -q export db" -> 70;
 * "keepassxc-cli show db | export-csv out" -> 70;
 * "keepassxc-cli show db" -> 60;
 * "keepassxc-cli show db.kdbx # see export docs" -> 60 (prose word).
 * Accepted residual (same verdict as before the tightening): a
 * hyphenated export compound inside prose ("# see export-db docs") and
 * an option value directly followed by the literal token "export".
 *
 * Text resolution follows the house contract: kCommandLine ->
 * (PS_SCRIPT) kScriptBlockText -> kImage.
 *
 * Score contract: >=75 MALICIOUS, >=55 SUSPICIOUS, below 55 never stamped.
 * Alerts dedup per signal inside the dedup window.
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_PASSWORD_VAULT_DETECTOR_H
#define EDR_PASSWORD_VAULT_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class PasswordVaultDetector {
public:
    PasswordVaultDetector(bool enabled, uint32_t minScore,
                          uint32_t dedupWindowSeconds, size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        const char* tool = "";
    };

    bool Analyze(const std::string& lower, Finding* out) const;
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

#endif /* EDR_PASSWORD_VAULT_DETECTOR_H */
