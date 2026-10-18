#ifndef EDR_TASKSCHEDULER_PARSER_H
#define EDR_TASKSCHEDULER_PARSER_H

#include <string>
#include "event_bus.h"

namespace edr {

bool ParseTaskSchedulerXml(const std::wstring& xml, Event& event);

} // namespace edr

#endif
