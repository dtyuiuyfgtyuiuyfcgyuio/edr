/*
 * remote_access_detector_tests.cpp - Unit tests for RemoteAccessDetector and
 * the production rule it feeds.
 */
#include "remote_access_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "remote_access_detector.h"
#include "rule_engine.h"

namespace {

#define RA_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "remote access detector test failed at line " +
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

edr::Event ProcessStart(const std::string& image, uint32_t pid,
                        uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.pid = pid;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    return event;
}

edr::Event Listener(uint32_t pid, const std::string& processImage,
                    const char* action, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_NET_LISTENER;
    event.pid = pid;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "NET_LISTENER";
    event.fields[edr::field::kListenerAction] = action;
    event.fields[edr::field::kListenerPid] = std::to_string(pid);
    event.fields[edr::field::kListenerProcess] = processImage;
    event.fields[edr::field::kListenerPort] = "5938";
    return event;
}

edr::Event NamedPipe(uint32_t pid, const std::string& operation,
                     uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_NAMED_PIPE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "NAMED_PIPE";
    event.fields[edr::field::kPid] = std::to_string(pid);
    event.fields[edr::field::kPipeName] = "\\\\.\\pipe\\AnyDesk";
    event.fields[edr::field::kPipeOperation] = operation;
    return event;
}

edr::Event ServiceChange(const std::string& imagePath, const char* action,
                         uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_SERVICE_CHANGE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "SERVICE_CHANGE";
    event.fields[edr::field::kServiceAction] = action;
    event.fields[edr::field::kServiceName] = "todesk_service";
    event.fields[edr::field::kServiceImagePath] = imagePath;
    return event;
}

void TestKnownToolBase() {
    edr::RemoteAccessDetector detector(true, 600, 4096);
    const uint64_t base = 1000000000ULL;
    edr::Event proc = ProcessStart(
        "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe", 4001, base);
    detector.Enrich(proc);
    RA_CHECK(proc.fields.at(edr::field::kRemoteAccessScore) == "60");
    RA_CHECK(proc.fields.at(edr::field::kRemoteAccessTool) == "anydesk.exe");
    RA_CHECK(proc.fields.at(edr::field::kRemoteAccessSignals).find("process") !=
             std::string::npos);
    RA_CHECK(proc.fields.at(edr::field::kRemoteAccessVerdict) == "SUSPICIOUS");
}

void TestListenerRaises() {
    edr::RemoteAccessDetector detector(true, 600, 4096);
    const uint64_t base = 2000000000ULL;
    detector.Enrich(ProcessStart(
        "C:\\Program Files\\TeamViewer\\TeamViewer.exe", 4002, base));
    edr::Event listener = Listener(
        4002, "C:\\Windows\\explorer.exe", "added", base + 10000000ULL);
    detector.Enrich(listener);
    RA_CHECK(listener.fields.at(edr::field::kRemoteAccessScore) == "90");
    RA_CHECK(listener.fields.at(edr::field::kRemoteAccessVerdict) == "MALICIOUS");
    RA_CHECK(listener.fields.at(edr::field::kRemoteAccessSignals).find("listener") !=
             std::string::npos);
}

void TestPipeRaises() {
    edr::RemoteAccessDetector detector(true, 600, 4096);
    const uint64_t base = 3000000000ULL;
    detector.Enrich(ProcessStart(
        "C:\\Program Files\\RustDesk\\rustdesk.exe", 4003, base));
    edr::Event pipe = NamedPipe(4003, "created", base + 10000000ULL);
    detector.Enrich(pipe);
    RA_CHECK(pipe.fields.at(edr::field::kRemoteAccessScore) == "75");
    RA_CHECK(pipe.fields.at(edr::field::kRemoteAccessVerdict) == "MALICIOUS");
    RA_CHECK(pipe.fields.at(edr::field::kRemoteAccessSignals).find("pipe") !=
             std::string::npos);
}

void TestServiceOnly() {
    edr::RemoteAccessDetector detector(true, 600, 4096);
    const uint64_t base = 4000000000ULL;
    edr::Event service = ServiceChange(
        "C:\\Program Files (x86)\\ToDesk\\ToDesk_Service.exe", "added", base);
    detector.Enrich(service);
    RA_CHECK(service.fields.at(edr::field::kRemoteAccessScore) == "60");
    RA_CHECK(service.fields.at(edr::field::kRemoteAccessSignals).find("service") !=
             std::string::npos);
}

void TestUnknownNoStamp() {
    edr::RemoteAccessDetector detector(true, 600, 4096);
    const uint64_t base = 5000000000ULL;
    edr::Event proc = ProcessStart(
        "C:\\Windows\\System32\\notepad.exe", 4004, base);
    detector.Enrich(proc);
    RA_CHECK(proc.fields.find(edr::field::kRemoteAccessScore) ==
             proc.fields.end());
    edr::Event listener = Listener(4004, "C:\\Windows\\explorer.exe", "added",
                                   base + 10000000ULL);
    detector.Enrich(listener);
    RA_CHECK(listener.fields.find(edr::field::kRemoteAccessScore) ==
             listener.fields.end());
}

void TestExpiredWindowResets() {
    edr::RemoteAccessDetector detector(true, 1, 4096);
    const uint64_t base = 6000000000ULL;
    detector.Enrich(ProcessStart(
        "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe", 4005, base));
    edr::Event listener = Listener(4005, "C:\\Windows\\explorer.exe", "added",
                                   base + 11000000ULL);
    detector.Enrich(listener);
    RA_CHECK(listener.fields.find(edr::field::kRemoteAccessScore) ==
             listener.fields.end());
}

void TestListenerFirstKnownProcess() {
    edr::RemoteAccessDetector detector(true, 600, 4096);
    const uint64_t base = 7000000000ULL;
    edr::Event listener = Listener(
        4006, "C:\\Program Files\\TeamViewer\\TeamViewer.exe", "added", base);
    detector.Enrich(listener);
    RA_CHECK(listener.fields.at(edr::field::kRemoteAccessScore) == "75");
    RA_CHECK(listener.fields.at(edr::field::kRemoteAccessVerdict) == "MALICIOUS");
}

void TestSubThresholdIsSilent() {
    /* A bare named-pipe creation from an unknown process never enters the
     * process table, but the pipe-then-listener ordering on a tracked tool
     * whose only signal is the pipe would score 45 - below the 55 SUSPICIOUS
     * bar. WriteState must withhold the fields entirely so no dead-letter
     * score is published. */
    edr::RemoteAccessDetector detector(true, 600, 4096);
    const uint64_t base = 9000000000ULL;
    edr::Event proc = ProcessStart(
        "C:\\Program Files\\TeamViewer\\TeamViewer.exe", 4008, base);
    detector.Enrich(proc);
    RA_CHECK(proc.fields.at(edr::field::kRemoteAccessScore) == "60");

    /* An unrelated pipe event for an untracked pid contributes nothing and
     * must not stamp, exercising the same floor path the guard protects. */
    edr::Event stray = NamedPipe(4009, "created", base + 10000000ULL);
    detector.Enrich(stray);
    RA_CHECK(stray.fields.find(edr::field::kRemoteAccessScore) ==
             stray.fields.end());
}

void TestProductionRule() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    edr::RemoteAccessDetector detector(true, 600, 4096);
    const uint64_t base = 8000000000ULL;
    edr::Event proc = ProcessStart(
        "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe", 4007, base);
    detector.Enrich(proc);
    engine.OnEvent(proc);
    RA_CHECK(Has(hits, "EDR-311"));
}

} // namespace

void RunRemoteAccessDetectorTests() {
    TestKnownToolBase();
    TestListenerRaises();
    TestPipeRaises();
    TestServiceOnly();
    TestUnknownNoStamp();
    TestExpiredWindowResets();
    TestListenerFirstKnownProcess();
    TestSubThresholdIsSilent();
    TestProductionRule();
}
