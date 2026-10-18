/*
 * hidden_user_account_detector.h - Hidden local account detector
 * (T1564.002).
 *
 * Windows hides an account from the logon screen and from the Start
 * menu user list when its name is written under:
 *
 *   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\
 *       SpecialAccounts\UserList
 *
 * as a REG_DWORD value with data 0 (data 1 makes it visible again). It
 * is the standard concealment step after an attacker adds a backdoor
 * local administrator: `net user backdoor /add` followed by a
 * SpecialAccounts\UserList write leaves an account that authenticates
 * normally but never appears in the UI. This detector owns both planes
 * that create it:
 *
 *   Registry plane (EDR_EVT_REG_WRITE) - the canonical write, in the
 *   two shapes the collectors emit (see CLAUDE.md registry contract):
 *     - snapshot shape (sysmon / reg_watch / reg_baseline): kRegKey is
 *       the FULL path ending in the account name, kRegValue is the value
 *       DATA ("0" hides).
 *     - driver shape (driver / imonitor): kRegKey ends at ...\UserList
 *       and kRegValue is the value NAME (the account); the kernel event
 *       carries no data.
 *
 *   Command plane (EDR_EVT_PROCESS_START / EDR_EVT_POWERSHELL_SCRIPT) -
 *   `reg add ...\SpecialAccounts\UserList /v <name> /t REG_DWORD /d 0`
 *   and the New-ItemProperty / Set-ItemProperty equivalents, where the
 *   command text states the data explicitly. Only a write verb counts:
 *   `reg query` (a read) and `reg delete` (which un-hides the account)
 *   stay silent.
 *
 * Tiers:
 *   85 hidden_user_account   a UserList value written with data 0, or a
 *                            command plane write whose text carries an
 *                            explicit zero-data shape (/d 0, dword:0,
 *                            -Value 0, = 0). This is the concealment
 *                            itself.
 *   75 hidden_user_write     a UserList value write whose data is not
 *                            readable (driver shape) - the account is
 *                            named but the value cannot be confirmed.
 *   70 hidden_user_visible   a UserList value written with non-zero data
 *                            (an account being un-hidden, or a benign
 *                            UserList edit).
 *   65 hidden_user_cmd_write a command plane reference to the UserList
 *                            path without a recognizable zero-data shape.
 *
 * Deliberate silences: reads of the key (no REG_WRITE), writes to other
 * SpecialAccounts subkeys, and any registry path that merely mentions
 * "userlist" without the SpecialAccounts parent pair.
 *
 * Verdict contract: >=75 MALICIOUS, >=55 SUSPICIOUS, below 55 never
 * stamped (the min_score gate runs first; a sub-55 finding early-exits).
 *
 * Dedup: key is "signal|account" (the account is the meaningful unit -
 * hiding two different accounts alerts twice, re-hiding the same one
 * inside the window is suppressed). State capacity overflow clears the
 * dedup map (same policy as netprovider_persist_detector).
 *
 * Thread-safety: no internal synchronization; only the single EventBus
 * consumer thread calls Enrich (see main.cpp).
 */
#ifndef EDR_HIDDEN_USER_ACCOUNT_DETECTOR_H
#define EDR_HIDDEN_USER_ACCOUNT_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

class HiddenUserAccountDetector {
public:
    HiddenUserAccountDetector(bool enabled, uint32_t minScore,
                              uint32_t dedupWindowSeconds,
                              size_t stateCapacity);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

    size_t StateCount() const { return m_lastAlert.size(); }

private:
    struct Finding {
        uint32_t score = 0;
        const char* signal = "";
        std::string account;
        std::string key;
    };

    bool AnalyzeRegistry(const std::string& regKey,
                         const std::string& regValue, Finding* out) const;
    bool AnalyzeCommandText(const std::string& lower, Finding* out) const;
    void Stamp(Event& event, const Finding& finding);

    bool m_enabled;
    uint32_t m_minScore;
    uint64_t m_dedupWindow100ns;
    size_t m_stateCapacity;

    /* dedup key (signal|account) -> ts100ns of last stamped alert. */
    std::unordered_map<std::string, uint64_t> m_lastAlert;

    static constexpr uint64_t kFiletimeTicksPerSecond = 10000000ULL;
};

} // namespace edr

#endif /* EDR_HIDDEN_USER_ACCOUNT_DETECTOR_H */
