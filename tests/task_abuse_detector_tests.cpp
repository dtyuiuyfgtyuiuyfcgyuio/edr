/*
 * task_abuse_detector_tests.cpp - Unit tests for TaskAbuseDetector.
 */
#include "task_abuse_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "task_abuse_detector.h"

namespace {

#define TASK_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "task abuse detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event TaskEvent(uint64_t ts100ns, const char* operation,
                     const char* taskName, const char* userContext) {
    edr::Event event;
    event.type = EDR_EVT_TASK_SCHEDULER;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "TASK_SCHEDULER";
    event.fields[edr::field::kSource] = "taskscheduler_log";
    event.fields[edr::field::kOperationType] = operation;
    if (taskName != nullptr)
        event.fields[edr::field::kTaskName] = taskName;
    if (userContext != nullptr)
        event.fields[edr::field::kTaskUserContext] = userContext;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kTaskAbuseScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

edr::TaskAbuseDetector::Settings DefaultSettings() {
    edr::TaskAbuseDetector::Settings settings;
    settings.enabled = true;
    settings.minScore = 55;
    settings.dedupWindowSeconds = 300;
    settings.stateCapacity = 1024;
    settings.deleteBurstThreshold = 3; /* small threshold for tests */
    settings.deleteBurstWindowSeconds = 60;
    return settings;
}

} // namespace

void RunTaskAbuseDetectorTests() {
    {
        /* Disabled detector never stamps. */
        edr::TaskAbuseDetector::Settings settings = DefaultSettings();
        settings.enabled = false;
        edr::TaskAbuseDetector detector(settings);
        edr::Event event =
            TaskEvent(1000 * kSecond, "TASK_REGISTERED",
                      "\\temp\\evil\\update.ps1", "CORP\\alice");
        detector.Enrich(event);
        TASK_CHECK(!HasScore(event));
    }
    {
        /* RTLO character in the task name -> 75 malicious. */
        edr::TaskAbuseDetector detector(DefaultSettings());
        std::string name = "invoice";
        name += "\xE2\x80\xAE";
        name += "exe.txt";
        edr::Event event = TaskEvent(
            1000 * kSecond, "TASK_REGISTERED", name.c_str(),
            "CORP\\alice");
        detector.Enrich(event);
        TASK_CHECK(HasScore(event));
        TASK_CHECK(event.fields.at(edr::field::kTaskAbuseScore) == "75");
        TASK_CHECK(event.fields.at(edr::field::kTaskAbuseVerdict) ==
                   "malicious");
    }
    {
        /* Double extension in the name -> 75 malicious. */
        edr::TaskAbuseDetector detector(DefaultSettings());
        edr::Event event = TaskEvent(
            1000 * kSecond, "TASK_REGISTERED", "report.pdf.exe",
            "CORP\\alice");
        detector.Enrich(event);
        TASK_CHECK(event.fields.at(edr::field::kTaskAbuseScore) == "75");
    }
    {
        /* Interpreter keyword embedded in the name -> 70 suspicious. */
        edr::TaskAbuseDetector detector(DefaultSettings());
        edr::Event event = TaskEvent(
            1000 * kSecond, "TASK_REGISTERED",
            "\\temp\\payload\\run powershell hidden",
            "CORP\\alice");
        detector.Enrich(event);
        TASK_CHECK(event.fields.at(edr::field::kTaskAbuseScore) == "70");
        TASK_CHECK(event.fields.at(edr::field::kTaskAbuseVerdict) ==
                   "suspicious");
    }
    {
        /* Writable-path fragment in the name -> 70 suspicious. */
        edr::TaskAbuseDetector detector(DefaultSettings());
        edr::Event event = TaskEvent(
            1000 * kSecond, "TASK_REGISTERED",
            "c:\\users\\alice\\appdata\\roaming\\svc", "CORP\\alice");
        detector.Enrich(event);
        TASK_CHECK(event.fields.at(edr::field::kTaskAbuseScore) == "70");
    }
    {
        /* GUID-only registration -> 55 suspicious. */
        edr::TaskAbuseDetector detector(DefaultSettings());
        edr::Event event = TaskEvent(
            1000 * kSecond, "TASK_REGISTERED",
            "{12345678-9abc-def0-1234-56789abcdef0}", "CORP\\bob");
        detector.Enrich(event);
        TASK_CHECK(event.fields.at(edr::field::kTaskAbuseScore) == "55");
    }
    {
        /* Ordinary task names never score. */
        edr::TaskAbuseDetector detector(DefaultSettings());
        edr::Event event = TaskEvent(
            1000 * kSecond, "TASK_REGISTERED",
            "\\MicrosoftEdgeUpdateTaskMachineCore", "SYSTEM");
        detector.Enrich(event);
        TASK_CHECK(!HasScore(event));

        /* GUID shape mismatch must not fall into the GUID signal. */
        edr::Event malformed = TaskEvent(
            1001 * kSecond, "TASK_REGISTERED",
            "{12345678-9abc-def0-1234-56789abcdefZ}", "CORP\\bob");
        detector.Enrich(malformed);
        TASK_CHECK(!HasScore(malformed));
    }
    {
        /* Mass deletion burst: below threshold silent, at threshold
         * fires once per wave. */
        edr::TaskAbuseDetector detector(DefaultSettings());
        const char* user = "CORP\\eve";
        for (int i = 0; i < 2; ++i) {
            edr::Event quiet = TaskEvent(
                static_cast<uint64_t>(2000 + i) * kSecond,
                "TASK_DELETED", nullptr, user);
            detector.Enrich(quiet);
            TASK_CHECK(!HasScore(quiet));
        }
        edr::Event burst = TaskEvent(2002 * kSecond, "TASK_DELETED",
                                     nullptr, user);
        detector.Enrich(burst);
        TASK_CHECK(HasScore(burst));
        TASK_CHECK(burst.fields.at(edr::field::kTaskAbuseScore) == "60");

        /* Next single delete is outside a new burst -> silent again. */
        edr::Event after = TaskEvent(2100 * kSecond, "TASK_DELETED",
                                     nullptr, user);
        detector.Enrich(after);
        TASK_CHECK(!HasScore(after));
    }
    {
        /* Dedup window: same suspicious task name registered twice
         * inside the window only alerts once. */
        edr::TaskAbuseDetector detector(DefaultSettings());
        edr::Event first = TaskEvent(3000 * kSecond, "TASK_REGISTERED",
                                     "x.pdf.exe", "CORP\\dave");
        detector.Enrich(first);
        TASK_CHECK(HasScore(first));
        edr::Event repeat = TaskEvent(3100 * kSecond, "TASK_UPDATED",
                                      "x.pdf.exe", "CORP\\dave");
        detector.Enrich(repeat);
        TASK_CHECK(!HasScore(repeat));
        edr::Event expired = TaskEvent(3400 * kSecond, "TASK_UPDATED",
                                       "x.pdf.exe", "CORP\\dave");
        detector.Enrich(expired);
        TASK_CHECK(HasScore(expired));
    }
    {
        /* Inspects: only TASK_SCHEDULER. */
        TASK_CHECK(
            edr::TaskAbuseDetector::Inspects(EDR_EVT_TASK_SCHEDULER));
        TASK_CHECK(!edr::TaskAbuseDetector::Inspects(EDR_EVT_REG_WRITE));
        TASK_CHECK(
            !edr::TaskAbuseDetector::Inspects(EDR_EVT_PROCESS_START));
    }
}
