#ifndef EDR_SECURITY_LOG_PARSER_H
#define EDR_SECURITY_LOG_PARSER_H

#include <string>
#include "event_bus.h"

namespace edr {

bool ParseSecurityLogXml(const std::wstring& xml, Event& event);

} // namespace edr

#endif