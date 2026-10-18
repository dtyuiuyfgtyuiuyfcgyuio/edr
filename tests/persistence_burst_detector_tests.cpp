/*
 * persistence_burst_detector_tests.cpp - Unit tests.
 */
#include "persistence_burst_detector_tests.h"

#include <cstdint>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "persistence_burst_detector.h"

namespace {

#define PB_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "persistence burst detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

constexpr uint64_t kSecond = 10000000ULL;

edr::Event ServiceEvent(uint64_t ts, const char* name,
                        const char* action) {
    edr::Event event;
    event.type = EDR_EVT_SERVICE_CHANGE;
    event.ts100ns = ts;
    event.fields[edr::field::kType] = "SERVICE_CHANGE";
    event.fields[edr::field::kServiceName] = name;
    event.fields[edr::field::kServiceAction] = action;
    return event;
}

edr::Event RegEvent(uint64_t ts, const char* key, const char* value) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = key;
    event.fields[edr::field::kRegValue] = value;
    return event;
}

edr::Event TaskEvent(uint64_t ts, const char* name, const char* op) {
    edr::Event event;
    event.type = EDR_EVT_TASK_SCHEDULER;
    event.ts100ns = ts;
    event.fields[edr::field::kType] = "TASK_SCHEDULER";
    event.fields[edr::field::kTaskName] = name;
    event.fields[edr::field::kOperationType] = op;
    return event;
}

edr::Event WmiEvent(uint64_t ts, const char* query) {
    edr::Event event;
    event.type = EDR_EVT_WMI_EVENT;
    event.ts100ns = ts;
    event.fields[edr::field::kType] = "WMI_EVENT";
    event.fields[edr::field::kWmiQuery] = query;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kPersistBurstScore) !=
           event.fields.end();
}

} // namespace

void RunPersistenceBurstDetectorTests() {
    std::fprintf(stderr, "[persist-burst] TestDisabled\n");
    {
        edr::PersistenceBurstDetector detector(false, 300, 1024, 55, 300);
        edr::Event event = ServiceEvent(1000 * kSecond, "Bad", "added");
        detector.Enrich(event);
        PB_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[persist-burst] TestSingleMechanismSilent\n");
    {
        /* One service = 35, below the 55 threshold. */
        edr::PersistenceBurstDetector detector(true, 300, 1024, 55, 300);
        edr::Event event = ServiceEvent(1000 * kSecond, "Svc1", "added");
        detector.Enrich(event);
        PB_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[persist-burst] TestTwoServices\n");
    {
        /* Two distinct services = 70 -> malicious. */
        edr::PersistenceBurstDetector detector(true, 300, 1024, 55, 300);
        edr::Event first = ServiceEvent(1000 * kSecond, "Svc1", "added");
        detector.Enrich(first);
        PB_CHECK(!HasScore(first));
        edr::Event second = ServiceEvent(1001 * kSecond, "Svc2", "added");
        detector.Enrich(second);
        PB_CHECK(HasScore(second));
        PB_CHECK(second.fields.at(edr::field::kPersistBurstScore) == "70");
        PB_CHECK(second.fields.at(edr::field::kPersistBurstMechanisms)
                     .find("service") != std::string::npos);
    }
    std::fprintf(stderr, "[persist-burst] TestSameKeyNotDoubleCounted\n");
    {
        /* Re-modifying the same service stays at 35 (deduped key). */
        edr::PersistenceBurstDetector detector(true, 300, 1024, 55, 300);
        edr::Event first = ServiceEvent(1000 * kSecond, "Svc1", "added");
        detector.Enrich(first);
        edr::Event repeat = ServiceEvent(1002 * kSecond, "Svc1", "modified");
        detector.Enrich(repeat);
        PB_CHECK(!HasScore(repeat));
    }
    std::fprintf(stderr, "[persist-burst] TestMixedMechanisms\n");
    {
        /* svc(35) + reg(30) = 65; +task(20) = 85; +wmi(25) = 100 capped,
         * plus the 3+ mechanism bonus is absorbed by the cap. */
        edr::PersistenceBurstDetector detector(true, 300, 1024, 55, 300);
        edr::Event svc = ServiceEvent(1000 * kSecond, "Svc1", "added");
        detector.Enrich(svc);
        edr::Event reg = RegEvent(
            1001 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Updater");
        detector.Enrich(reg);
        PB_CHECK(reg.fields.at(edr::field::kPersistBurstScore) == "65");
        edr::Event task = TaskEvent(1002 * kSecond, "EvilTask",
                                    "task_registered");
        detector.Enrich(task);
        PB_CHECK(task.fields.at(edr::field::kPersistBurstScore) == "85");
        PB_CHECK(task.fields.at(edr::field::kPersistBurstVerdict) ==
                 "malicious");
        edr::Event wmi = WmiEvent(
            1003 * kSecond,
            "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE "
            "TargetInstance ISA 'Win32_Process'");
        detector.Enrich(wmi);
        PB_CHECK(!HasScore(wmi)); /* no persistence keywords -> ignored */
    }
    std::fprintf(stderr, "[persist-burst] TestWmiConsumerCounted\n");
    {
        /* WMI event-consumer subscription counts as a mechanism. */
        edr::PersistenceBurstDetector detector(true, 300, 1024, 55, 300);
        edr::Event filter = WmiEvent(
            1000 * kSecond,
            "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE "
            "TargetInstance ISA 'Win32_Process'");
        detector.Enrich(filter);
        PB_CHECK(!HasScore(filter)); /* no consumer yet -> not counted */
        edr::Event svc = ServiceEvent(1001 * kSecond, "Svc1", "added");
        detector.Enrich(svc);
        edr::Event reg = RegEvent(
            1002 * kSecond,
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "Drop");
        detector.Enrich(reg);
        PB_CHECK(reg.fields.at(edr::field::kPersistBurstScore) == "65");
    }
    std::fprintf(stderr, "[persist-burst] TestIrrelevantEventsSilent\n");
    {
        edr::PersistenceBurstDetector detector(true, 300, 1024, 55, 300);
        edr::Event benignReg = RegEvent(
            1000 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\SomeProduct\\Settings",
            "InstallPath");
        detector.Enrich(benignReg);
        PB_CHECK(!HasScore(benignReg));
        edr::Event benignTask = TaskEvent(1001 * kSecond, "Defrag",
                                          "task_completed");
        detector.Enrich(benignTask);
        PB_CHECK(!HasScore(benignTask));
        edr::Event removedSvc = ServiceEvent(1002 * kSecond, "Svc",
                                             "removed");
        detector.Enrich(removedSvc);
        PB_CHECK(!HasScore(removedSvc));
    }
    std::fprintf(stderr, "[persist-burst] TestWindowExpiry\n");
    {
        /* Mechanisms expire; after the window the score resets. */
        edr::PersistenceBurstDetector detector(true, 300, 1024, 55, 300);
        edr::Event svc = ServiceEvent(1000 * kSecond, "Svc1", "added");
        detector.Enrich(svc);
        edr::Event reg = RegEvent(
            1001 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Updater");
        detector.Enrich(reg);
        PB_CHECK(reg.fields.at(edr::field::kPersistBurstScore) == "65");
        edr::Event late = RegEvent(
            1001 * kSecond + 301 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Later");
        detector.Enrich(late);
        PB_CHECK(!HasScore(late));
    }
    std::fprintf(stderr, "[persist-burst] TestInspects\n");
    {
        PB_CHECK(edr::PersistenceBurstDetector::Inspects(
            EDR_EVT_REG_WRITE));
        PB_CHECK(edr::PersistenceBurstDetector::Inspects(
            EDR_EVT_SERVICE_CHANGE));
        PB_CHECK(edr::PersistenceBurstDetector::Inspects(
            EDR_EVT_TASK_SCHEDULER));
        PB_CHECK(edr::PersistenceBurstDetector::Inspects(
            EDR_EVT_WMI_EVENT));
        PB_CHECK(!edr::PersistenceBurstDetector::Inspects(
            EDR_EVT_PROCESS_START));
    }
    std::fprintf(stderr, "[persist-burst] all passed\n");
}
