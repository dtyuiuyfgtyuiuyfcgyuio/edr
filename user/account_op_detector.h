/*
 * account_op_detector.h - Account operation detector
 * (MITRE T1136.001 Create Account, T1098.001 Additional Cloud Roles /
 * local admin group addition, T1087.001 Account Discovery, T1078,
 * T1531 Account Access Removal).
 *
 * Inspects EDR_EVT_PROCESS_START events for account-management commands
 * executed through net.exe / net1.exe / dsadd.exe:
 *  - creation of local accounts (net user <n> <p> /add)
 *  - deletion of local accounts (net user <n> /delete, T1531)
 *  - enabling disabled accounts (net user <n> /active:yes)
 *  - disabling accounts (net user <n> /active:no, T1531)
 *  - addition of a user to local groups, especially administrators
 *    (net localgroup administrators <n> /add)
 *  - addition to domain groups (net group "Domain Admins" <n> /add)
 *  - password resets (net user <n> <new-password>)
 *  - account policy weakening (net accounts ...)
 * Events are stamped with account_op_* fields only when the FINAL
 * aggregated score reaches the 55 alert band (house verdict contract:
 * >= 55 SUSPICIOUS, >= 75 MALICIOUS). Sub-55 findings - e.g. the 50-point
 * account_enable signal - are classified by ClassifyAccountOperation but
 * deliberately NOT stamped, because no rule consumes the 50-54 dead band
 * (house score regex ^(?:5[5-9]|[6-9][0-9]|100)$); stamping them would be
 * a dead letter.
 * The detector is stateless: every interesting PROCESS_START is scored
 * immediately.
 */
#ifndef EDR_ACCOUNT_OP_DETECTOR_H
#define EDR_ACCOUNT_OP_DETECTOR_H

#include <cstdint>
#include <string>

#include "edr_event.h"
#include "event_bus.h"

namespace edr {

struct AccountOpSignal {
    bool suspicious = false;
    uint32_t score = 0;
    std::string signals;  /* comma-separated signal names */
    std::string command;  /* normalized command type */
    std::string verdict;
};

/* Pure classification helper, exposed for unit tests.
 * Note the field semantics: `suspicious`/`score`/`signals` report any
 * classified signal (even sub-55 ones like account_enable 50), while
 * `verdict` follows the house band and is EMPTY below 55 - the empty
 * verdict is exactly what gates event stamping in Enrich. */
AccountOpSignal ClassifyAccountOperation(const std::string& image,
                                         const std::string& commandLine);

class AccountOpDetector {
public:
    explicit AccountOpDetector(bool enabled);

    void Enrich(Event& event);

    static bool Inspects(uint16_t type);

private:
    bool m_enabled;
};

} // namespace edr

#endif /* EDR_ACCOUNT_OP_DETECTOR_H */
