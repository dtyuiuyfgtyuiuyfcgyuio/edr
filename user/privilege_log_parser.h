#ifndef EDR_PRIVILEGE_LOG_PARSER_H
#define EDR_PRIVILEGE_LOG_PARSER_H

#include <string>
#include "event_bus.h"

namespace edr {

bool ParsePrivilegeLogXml(const std::wstring& xml, Event& event);

} // namespace edr

#endif
