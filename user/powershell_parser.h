#ifndef EDR_POWERSHELL_PARSER_H
#define EDR_POWERSHELL_PARSER_H

#include <cstddef>
#include <string>

#include "event_bus.h"

namespace edr {

bool ParsePowerShellXml(const std::wstring& xml, size_t maxScriptChars,
                        Event& event);

} // namespace edr

#endif /* EDR_POWERSHELL_PARSER_H */
