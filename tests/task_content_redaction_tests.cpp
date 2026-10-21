#include <cstdio>
#include <string>

#include "alerter.h"
#include "edr_event.h"
#include "json_lite.h"

namespace {
int failures = 0;
#define CHECK(value) do { if (!(value)) { \
    std::fprintf(stderr, "check failed at %d: %s\n", __LINE__, #value); \
    ++failures; } } while (0)

void TestTaskDefinitionsFollowTheScriptBodyRedactionContract() {
    edr::Event event;
    event.type = EDR_EVT_TASK_SCHEDULER;
    event.source = "security_log";
    event.ts100ns = 134370000000000000ULL;
    const std::string content =
        "<Task><Actions><Exec><Arguments>--token=task-secret-123</Arguments>"
        "</Exec></Actions></Task>";
    event.fields["task_content"] = content;
    event.fields["task_content_status"] = "captured";
    event.fields["task_name"] = "\\Maintenance";
    edr::Alert alert{"EDR-032", "high", "alert", &event, {}, {}};
    const auto eventJson = jsonlite::parse(edr::EventToJsonLine(event, true));
    const auto alertJson = jsonlite::parse(edr::AlertToJsonLine(alert, true));
    for (const auto* row : {&eventJson, &alertJson}) {
        const auto* fields = row->find("fields");
        CHECK(fields != nullptr);
        if (!fields) continue;
        CHECK(fields->find("task_content")->asString() == "[redacted]");
        CHECK(fields->find("task_content_status")->asString() == "captured");
        CHECK(fields->find("task_name")->asString() == "\\Maintenance");
    }
    CHECK(edr::EventToJsonLine(event, true).find("task-secret-123") == std::string::npos);
    CHECK(edr::AlertToJsonLine(alert, true).find("task-secret-123") == std::string::npos);
    const auto rawEvent = jsonlite::parse(edr::EventToJsonLine(event, false));
    const auto rawAlert = jsonlite::parse(edr::AlertToJsonLine(alert, false));
    CHECK(rawEvent.find("fields")->find("task_content")->asString() == content);
    CHECK(rawAlert.find("fields")->find("task_content")->asString() == content);

    // The event identifier must reflect the same exported fields as the body.
    event.fields["task_content"] = "<Task>different private command</Task>";
    const auto otherRedacted = jsonlite::parse(edr::EventToJsonLine(event, true));
    const auto otherRaw = jsonlite::parse(edr::EventToJsonLine(event, false));
    CHECK(eventJson.find("eventId")->asString() == otherRedacted.find("eventId")->asString());
    CHECK(rawEvent.find("eventId")->asString() != otherRaw.find("eventId")->asString());
}
}

int main() {
    TestTaskDefinitionsFollowTheScriptBodyRedactionContract();
    if (failures) return 1;
    std::puts("task content serialization/redaction tests passed");
    return 0;
}
