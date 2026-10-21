#ifndef EDR_TASKSCHEDULER_PARSER_H
#define EDR_TASKSCHEDULER_PARSER_H

#include <string>
#include "event_bus.h"

namespace edr {

bool ParseTaskSchedulerXml(const std::wstring& xml, Event& event);

/* Shared by the live collector and contract tests so every accepted parser ID
 * is visible to the same Event Log subscription. */
std::wstring BuildTaskSchedulerSubscriptionQuery();

} // namespace edr

#endif
