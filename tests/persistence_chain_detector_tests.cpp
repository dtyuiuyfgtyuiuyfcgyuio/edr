/*
 * persistence_chain_detector_tests.cpp - Unit tests for
 * PersistenceChainDetector and the production rule it feeds (EDR-251).
 */
#include "persistence_chain_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "persistence_chain_detector.h"
#include "rule_engine.h"

namespace {

#define PC_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "persistence chain detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

const char* ProductionRulesPath() {
    return GetFileAttributesA("..\\rules\\rules.json") !=
                   INVALID_FILE_ATTRIBUTES
        ? "..\\rules\\rules.json"
        : "rules\\rules.json";
}

bool Has(const std::vector<std::string>& hits, const char* id) {
    return std::find(hits.begin(), hits.end(), id) != hits.end();
}

edr::Event PersistenceEvent(uint16_t type, const char* typeName,
                            uint32_t pid, const char* image,
                            uint64_t ts100ns) {
    edr::Event event;
    event.type = type;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.fields[edr::field::kType] = typeName;
    if (image) event.fields[edr::field::kImage] = image;
    return event;
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

void TestPidZeroIgnored() {
    edr::PersistenceChainDetector detector(true, 600, 4096, 3);
    edr::Event event =
        PersistenceEvent(EDR_EVT_REG_WRITE, "REG_WRITE", 0,
                         "C:\\evil\\persist.exe", 1000);
    event.fields[edr::field::kRegKey] =
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater";
    detector.Enrich(event);
    PC_CHECK(!HasField(event, edr::field::kPersistChainScore));
    PC_CHECK(detector.StateCount() == 0);
}

void TestNonPersistenceIgnored() {
    edr::PersistenceChainDetector detector(true, 600, 4096, 3);

    /* REG_WRITE outside the persistence key set is not a mechanism. */
    edr::Event other;
    other.type = EDR_EVT_REG_WRITE;
    other.ts100ns = 1000;
    other.pid = 100;
    other.fields[edr::field::kType] = "REG_WRITE";
    other.fields[edr::field::kRegKey] =
        "HKLM\\SOFTWARE\\SomeApp\\Settings";
    detector.Enrich(other);
    PC_CHECK(!HasField(other, edr::field::kPersistChainScore));
    PC_CHECK(detector.StateCount() == 0);

    /* Unrelated event types are ignored. */
    edr::Event net = PersistenceEvent(EDR_EVT_NET_CONNECT, "NET_CONNECT",
                                      100, "C:\\app.exe", 2000);
    net.fields[edr::field::kDstIp] = "10.0.0.1";
    detector.Enrich(net);
    PC_CHECK(detector.StateCount() == 0);
}

void TestSingleMechanismNoStamp() {
    edr::PersistenceChainDetector detector(true, 600, 4096, 3);
    edr::Event run =
        PersistenceEvent(EDR_EVT_REG_WRITE, "REG_WRITE", 100,
                         "C:\\evil\\persist.exe", 1000);
    run.fields[edr::field::kRegKey] =
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater";
    detector.Enrich(run);
    PC_CHECK(!HasField(run, edr::field::kPersistChainScore));

    /* Second distinct mechanism -> 2 of 3, still below threshold. */
    edr::Event task =
        PersistenceEvent(EDR_EVT_TASK_SCHEDULER, "TASK_SCHEDULER", 100,
                         "C:\\evil\\persist.exe", 2000);
    task.fields[edr::field::kTaskName] = "Updater";
    detector.Enrich(task);
    PC_CHECK(!HasField(task, edr::field::kPersistChainScore));
    PC_CHECK(detector.StateCount() == 1);
}

void TestThreeMechanismsStamp() {
    edr::PersistenceChainDetector detector(true, 600, 4096, 3);
    edr::Event run =
        PersistenceEvent(EDR_EVT_REG_WRITE, "REG_WRITE", 100,
                         "C:\\evil\\persist.exe", 1000);
    run.fields[edr::field::kRegKey] =
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater";
    detector.Enrich(run);

    edr::Event task =
        PersistenceEvent(EDR_EVT_TASK_SCHEDULER, "TASK_SCHEDULER", 100,
                         "C:\\evil\\persist.exe", 2000);
    task.fields[edr::field::kTaskName] = "Updater";
    detector.Enrich(task);

    edr::Event service =
        PersistenceEvent(EDR_EVT_SERVICE_CHANGE, "SERVICE_CHANGE", 100,
                         "C:\\evil\\persist.exe", 3000);
    service.fields[edr::field::kServiceAction] = "added";
    service.fields[edr::field::kServiceName] = "UpdaterSvc";
    detector.Enrich(service);

    PC_CHECK(HasField(service, edr::field::kPersistChainScore));
    PC_CHECK(service.fields[edr::field::kPersistChainScore] == "75");
    PC_CHECK(service.fields[edr::field::kPersistChainCount] == "3");
    PC_CHECK(service.fields[edr::field::kPersistChainMechanisms] ==
             "run_key,scheduled_task,service");
    PC_CHECK(service.fields[edr::field::kPersistChainWindowSeconds] == "600");
}

void TestMechanismExtraction() {
    edr::PersistenceChainDetector detector(true, 600, 4096, 2);

    struct Case {
        uint16_t type;
        const char* typeName;
        const char* key;
        const char* value;
        const char* expected; /* comma-joined mechanism list after this event */
    };
    const Case cases[] = {
        {EDR_EVT_REG_WRITE, "REG_WRITE",
         "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\X",
         "", "run_key"},
        {EDR_EVT_REG_WRITE, "REG_WRITE",
         "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe",
         "Debugger", "ifeo_debugger,run_key"},
        {EDR_EVT_REG_WRITE, "REG_WRITE",
         "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
         "Shell", "ifeo_debugger,run_key,winlogon"},
        {EDR_EVT_REG_WRITE, "REG_WRITE",
         "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
         "AppInit_DLLs", "appinit_dlls,ifeo_debugger,run_key,winlogon"},
        {EDR_EVT_REG_WRITE, "REG_WRITE",
         "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
         "SecurityPackages", "appinit_dlls,ifeo_debugger,lsa_packages,run_key,winlogon"},
        {EDR_EVT_REG_WRITE, "REG_WRITE",
         "HKLM\\SOFTWARE\\Classes\\CLSID\\{ABC}\\InProcServer32",
         "", "appinit_dlls,com_inproc,ifeo_debugger,lsa_packages,run_key,winlogon"},
        {EDR_EVT_FILE_CREATE, "FILE_CREATE",
         "C:\\Users\\Public\\Desktop\\note.txt", "",
         "appinit_dlls,com_inproc,ifeo_debugger,lsa_packages,run_key,winlogon"},
        {EDR_EVT_FILE_CREATE, "FILE_CREATE",
         "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\evil.exe", "",
         "appinit_dlls,com_inproc,ifeo_debugger,lsa_packages,run_key,startup_folder,winlogon"},
        {EDR_EVT_WMI_EVENT, "WMI_EVENT",
         "", "", "appinit_dlls,com_inproc,ifeo_debugger,lsa_packages,run_key,startup_folder,winlogon"},
        {EDR_EVT_WMI_EVENT, "WMI_EVENT",
         "", "", "appinit_dlls,com_inproc,ifeo_debugger,lsa_packages,run_key,startup_folder,winlogon,wmi_subscription"},
    };

    uint64_t ts = 1000;
    edr::Event lastStamped;
    for (const Case& c : cases) {
        edr::Event event = PersistenceEvent(c.type, c.typeName, 77,
                                            "C:\\evil\\persist.exe", ts);
        if (c.key) event.fields[edr::field::kRegKey] = c.key;
        if (c.value) event.fields[edr::field::kRegValue] = c.value;
        if (c.typeName == std::string("FILE_CREATE") && c.key)
            event.fields[edr::field::kFilePath] = c.key;
        if (c.typeName == std::string("WMI_EVENT"))
            event.fields[edr::field::kWmiEventId] = "5861";
        detector.Enrich(event);
        if (HasField(event, edr::field::kPersistChainScore))
            lastStamped = event;
        ts += 1000;
    }
    /* The WMI event that brings the chain to 8 mechanisms must stamp with
     * the full sorted list (threshold 2, escalation re-stamp). */
    PC_CHECK(HasField(lastStamped, edr::field::kPersistChainScore));
    PC_CHECK(lastStamped.fields[edr::field::kPersistChainScore] == "100");
    PC_CHECK(lastStamped.fields[edr::field::kPersistChainCount] == "8");
    PC_CHECK(lastStamped.fields[edr::field::kPersistChainMechanisms] ==
             "appinit_dlls,com_inproc,ifeo_debugger,lsa_packages,run_key,"
             "startup_folder,winlogon,wmi_subscription");
    PC_CHECK(detector.StateCount() == 1);
}

void TestWindowExpiryResetsFlag() {
    edr::PersistenceChainDetector detector(true, 60, 4096, 2);

    edr::Event run =
        PersistenceEvent(EDR_EVT_REG_WRITE, "REG_WRITE", 100,
                         "C:\\evil\\persist.exe", 1000);
    run.fields[edr::field::kRegKey] =
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\X";
    detector.Enrich(run);

    edr::Event task =
        PersistenceEvent(EDR_EVT_TASK_SCHEDULER, "TASK_SCHEDULER", 100,
                         "C:\\evil\\persist.exe", 2000);
    task.fields[edr::field::kTaskName] = "X";
    detector.Enrich(task);
    PC_CHECK(HasField(task, edr::field::kPersistChainScore));

    /* After the window (60 s = 6e8 ticks), both mechanisms expire. */
    edr::Event later =
        PersistenceEvent(EDR_EVT_SERVICE_CHANGE, "SERVICE_CHANGE", 100,
                         "C:\\evil\\persist.exe",
                         1000 + 600000000ULL + 5000ULL);
    later.fields[edr::field::kServiceAction] = "added";
    detector.Enrich(later);
    PC_CHECK(detector.StateCount() == 1);
    PC_CHECK(!HasField(later, edr::field::kPersistChainScore));
}

void TestCapacityEviction() {
    edr::PersistenceChainDetector detector(true, 600, 2, 2);
    for (uint32_t pid = 1; pid <= 5; ++pid) {
        edr::Event run =
            PersistenceEvent(EDR_EVT_REG_WRITE, "REG_WRITE", pid,
                             "C:\\evil\\p.exe", pid * 1000);
        run.fields[edr::field::kRegKey] =
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\X";
        detector.Enrich(run);
    }
    PC_CHECK(detector.StateCount() <= 2);
}

void TestRuleEdr251() {
    const char* path = ProductionRulesPath();
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        std::printf("skipping rule checks: rules file not found (%s)\n", path);
        return;
    }
    edr::RuleEngine engine;
    engine.LoadFromFile(path);

    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&hits](const edr::Alert& alert) { hits.push_back(alert.ruleId); });

    edr::Event event =
        PersistenceEvent(EDR_EVT_SERVICE_CHANGE, "SERVICE_CHANGE", 100,
                         "C:\\evil\\persist.exe", 3000);
    event.fields[edr::field::kServiceAction] = "added";
    event.fields[edr::field::kServiceName] = "Svc";
    /* A chain of 3 mechanisms (score 75) must hit EDR-251. */
    event.fields[edr::field::kPersistChainScore] = "75";
    event.fields[edr::field::kPersistChainMechanisms] =
        "run_key,scheduled_task,service";
    event.fields[edr::field::kPersistChainCount] = "3";
    event.fields[edr::field::kPersistChainWindowSeconds] = "600";
    engine.OnEvent(event);
    PC_CHECK(Has(hits, "EDR-251"));

    /* A low score must not hit EDR-251. */
    hits.clear();
    edr::Event low = event;
    low.fields[edr::field::kPersistChainScore] = "25";
    engine.OnEvent(low);
    PC_CHECK(!Has(hits, "EDR-251"));
}

} // namespace

void RunPersistenceChainDetectorTests() {
    TestPidZeroIgnored();
    TestNonPersistenceIgnored();
    TestSingleMechanismNoStamp();
    TestThreeMechanismsStamp();
    TestMechanismExtraction();
    TestWindowExpiryResetsFlag();
    TestCapacityEviction();
    TestRuleEdr251();
}
