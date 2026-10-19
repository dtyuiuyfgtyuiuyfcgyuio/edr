#ifndef EDR_SYSMON_PARSER_H
#define EDR_SYSMON_PARSER_H

#include <string>

#include "event_bus.h"

namespace edr {

bool ParseSysmonXml(const std::wstring& xml, Event& event);
std::wstring SysmonSubscriptionQuery(bool imageLoad, bool processAccess,
                                    bool remoteThread, bool namedPipe);

} // namespace edr

#endif
