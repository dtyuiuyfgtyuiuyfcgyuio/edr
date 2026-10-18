#ifndef EDR_SYSMON_PARSER_H
#define EDR_SYSMON_PARSER_H

#include <string>

#include "event_bus.h"

namespace edr {

bool ParseSysmonXml(const std::wstring& xml, Event& event);

} // namespace edr

#endif
