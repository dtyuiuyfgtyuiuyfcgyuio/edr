/*
 * telemetry_delivery.h - Event reporter and detection delivery boundary.
 */
#ifndef EDR_TELEMETRY_DELIVERY_H
#define EDR_TELEMETRY_DELIVERY_H

#include "event_bus.h"

namespace edr {

class Reporter;
class RuleEngine;

/* Queue one event for reporting, then evaluate it unless it is report-only.
 * Throws when reporting rejects the event or rule evaluation throws, allowing
 * EventBus consumption receipts to retain the source checkpoint. */
void DeliverTelemetryEvent(const Event& event, Reporter* reporter, bool redact,
                           RuleEngine* rules);

/* Used before any stateful enrichment. True means raw evidence was forwarded
 * and the caller must return without changing detector/process-tree state.
 * Reporting failures propagate so the source cannot acknowledge lost data. */
bool DeliverReportOnlyEvent(const Event& event, Reporter* reporter, bool redact,
                            RuleEngine* rules);

} // namespace edr

#endif /* EDR_TELEMETRY_DELIVERY_H */
