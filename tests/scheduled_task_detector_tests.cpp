#include "scheduled_task_detector_tests.h"

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "scheduled_task_detector.h"

namespace {
#define ST_CHECK(value) Check((value), #value, __LINE__)
void Check(bool value, const char* expression, int line) {
    if (!value) throw std::runtime_error("scheduled task test failed at line " +
        std::to_string(line) + ": " + expression);
}
edr::Event Task(const char* operation, const char* name, const char* user,
               uint64_t time) {
    edr::Event event;
    event.type = EDR_EVT_TASK_SCHEDULER;
    event.ts100ns = time;
    event.fields[edr::field::kOperationType] = operation;
    event.fields[edr::field::kTaskName] = name;
    event.fields[edr::field::kTaskUserContext] = user;
    return event;
}
void TestSuspiciousTask() {
    edr::ScheduledTaskDetector detector(true, 300, 128);
    edr::Event event = Task("TASK_REGISTERED", "\\Temp\\PowerShellUpdate",
                            "CORP\\alice", 1000000000ULL);
    detector.Enrich(event);
    ST_CHECK(event.fields.at(edr::field::kScheduledTaskScore) == "45");
    ST_CHECK(event.fields.at(edr::field::kScheduledTaskSignals).find("suspicious_task") != std::string::npos);
}
void TestRepeatedDeletion() {
    edr::ScheduledTaskDetector detector(true, 300, 128);
    const uint64_t base = 2000000000ULL;
    detector.Enrich(Task("TASK_REGISTERED", "\\Temp\\UpdateTask", "SYSTEM", base));
    edr::Event event = Task("TASK_DELETED", "\\Temp\\UpdateTask", "SYSTEM", base + 1);
    detector.Enrich(event);
    ST_CHECK(event.fields.at(edr::field::kScheduledTaskScore) == "80");
    ST_CHECK(event.fields.at(edr::field::kScheduledTaskVerdict) == "SUSPICIOUS");
}
void TestDisabled() {
    edr::ScheduledTaskDetector detector(false, 300, 128);
    edr::Event event = Task("TASK_REGISTERED", "\\Temp\\x", "user", 1);
    detector.Enrich(event);
    ST_CHECK(event.fields.find(edr::field::kScheduledTaskScore) == event.fields.end());
}
}
void RunScheduledTaskDetectorTests() {
    TestSuspiciousTask();
    TestRepeatedDeletion();
    TestDisabled();
}
