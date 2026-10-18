/*
 * process_access.h - Shared normalization of PROCESS_OPEN/PROCESS_ACCESS
 * granted-access masks into the common access-bits fields.
 *
 * Canonical granted access is rendered as "0x%08x". Each access bit is
 * emitted as an independent "true"/"false" field so rules can target
 * exactly the injection-relevant bits (create thread, VM write, ...).
 */
#ifndef EDR_PROCESS_ACCESS_H
#define EDR_PROCESS_ACCESS_H

#include <cstdio>

#include "event_bus.h"

namespace edr {

inline void ApplyProcessAccessFields(Event& event, uint32_t grantedAccess) {
    char canonicalAccess[11] = {};
    std::snprintf(canonicalAccess, sizeof(canonicalAccess), "0x%08x",
                  grantedAccess);
    event.fields[field::kGrantedAccess] = canonicalAccess;
    auto setAccess = [&](const char* name, uint32_t mask) {
        event.fields[name] = (grantedAccess & mask) != 0 ? "true" : "false";
    };
    setAccess(field::kAccessCreateThread, 0x0002);
    setAccess(field::kAccessVmOperation, 0x0008);
    setAccess(field::kAccessVmRead, 0x0010);
    setAccess(field::kAccessVmWrite, 0x0020);
    setAccess(field::kAccessDuplicateHandle, 0x0040);
    setAccess(field::kAccessQueryInformation, 0x0400);
    setAccess(field::kAccessQueryLimitedInformation, 0x1000);
}

} // namespace edr

#endif /* EDR_PROCESS_ACCESS_H */
