#ifndef EDR_QUARANTINE_RESTORE_TESTS_H
#define EDR_QUARANTINE_RESTORE_TESTS_H

#include <string>

void RunQuarantineRestoreTests();

/* Exact production-ACL integration test. Returns 77 with skipReason when the
 * current token is neither LocalSystem nor an enabled administrator. */
int RunQuarantineRestoreNativeTests(std::string& skipReason);

#endif /* EDR_QUARANTINE_RESTORE_TESTS_H */
