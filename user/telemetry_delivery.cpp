/*
 * telemetry_delivery.cpp - Reporter and detection sink composition.
 */
#include "telemetry_delivery.h"

#include <stdexcept>

#include "alerter.h"
#include "reporter.h"
#include "rule_engine.h"

namespace edr {

void DeliverTelemetryEvent(const Event& event, Reporter* reporter, bool redact,
                           RuleEngine* rules) {
    const bool reported = !reporter ||
        reporter->Enqueue(EventToJsonLine(event, redact));
    if (rules && event.disposition != EventDisposition::ReportOnly)
        rules->OnEvent(event);
    if (!reported) throw std::runtime_error("event reporter rejected event");
}

bool DeliverReportOnlyEvent(const Event& event, Reporter* reporter, bool redact,
                            RuleEngine* rules) {
    if (event.disposition != EventDisposition::ReportOnly) return false;
    DeliverTelemetryEvent(event, reporter, redact, rules);
    return true;
}

} // namespace edr
