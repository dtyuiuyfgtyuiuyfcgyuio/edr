#ifndef EDR_RDP_PARSER_H
#define EDR_RDP_PARSER_H

#include <string>

#include "event_bus.h"

namespace edr {

/* Parse TerminalServices LocalSessionManager 21/23/24/25 and
 * RemoteConnectionManager 1149 into an RDP_SESSION event. */
bool ParseRdpXml(const std::wstring& xml, Event& event);

} // namespace edr

#endif /* EDR_RDP_PARSER_H */
