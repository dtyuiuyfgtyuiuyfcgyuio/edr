#ifndef EDR_DEFENDER_PARSER_H
#define EDR_DEFENDER_PARSER_H

#include <string>

#include "event_bus.h"

namespace edr {

/* Parse selected Microsoft-Windows-Windows Defender/Operational events. */
bool ParseDefenderXml(const std::wstring& xml, Event& event);

} // namespace edr

#endif /* EDR_DEFENDER_PARSER_H */
