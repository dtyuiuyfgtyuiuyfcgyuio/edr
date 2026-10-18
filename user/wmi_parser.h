#ifndef EDR_WMI_PARSER_H
#define EDR_WMI_PARSER_H

#include <string>
#include "event_bus.h"

namespace edr {

bool ParseWmiXml(const std::wstring& xml, Event& event);

} // namespace edr

#endif