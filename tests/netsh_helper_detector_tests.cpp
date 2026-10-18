/*
 * netsh_helper_detector_tests.cpp - Unit tests for NetshHelperDetector
 * (T1546.007).
 */
#include "netsh_helper_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "netsh_helper_detector.h"

namespace {

#define NH_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "netsh helper detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcEvent(uint64_t ts100ns, const char* image,
                     const char* commandLine) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    if (commandLine != nullptr)
        event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

edr::Event ScriptEvent(uint64_t ts100ns, const char* script) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kImage] =
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    event.fields[edr::field::kScriptBlockText] = script;
    return event;
}

edr::Event RegEvent(uint64_t ts100ns, const char* key, const char* value) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = key;
    if (value != nullptr)
        event.fields[edr::field::kRegValue] = value;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kNetshHelperScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunNetshHelperDetectorTests() {
    std::fprintf(stderr, "[netsh-helper] TestDisabled\n");
    {
        edr::NetshHelperDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4200 * kSecond, "C:\\Windows\\System32\\netsh.exe",
            "netsh add helper C:\\Temp\\evil.dll");
        detector.Enrich(event);
        NH_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[netsh-helper] TestAddHelper\n");
    {
        edr::NetshHelperDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4201 * kSecond, "C:\\Windows\\System32\\netsh.exe",
            "netsh add helper C:\\Temp\\evil.dll");
        detector.Enrich(event);
        NH_CHECK(Score(event) == "90");
        NH_CHECK(event.fields.at(edr::field::kNetshHelperVerdict) ==
                 "malicious");
    }
    std::fprintf(stderr, "[netsh-helper] TestPowerShellWrap\n");
    {
        edr::NetshHelperDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(
            4202 * kSecond,
            "Start-Process netsh -ArgumentList "
            "'add helper C:\\Users\\Public\\h.dll'");
        detector.Enrich(event);
        NH_CHECK(Score(event) == "90");
    }
    std::fprintf(stderr, "[netsh-helper] TestRegAdd\n");
    {
        edr::NetshHelperDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4203 * kSecond, "C:\\Windows\\System32\\reg.exe",
            "reg add HKLM\\SOFTWARE\\Microsoft\\NetSh /v helper "
            "/d C:\\Temp\\evil.dll /f");
        detector.Enrich(event);
        NH_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[netsh-helper] TestRegWriteDriverShape\n");
    {
        edr::NetshHelperDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            4204 * kSecond, "HKLM\\SOFTWARE\\Microsoft\\NetSh",
            "evil");
        detector.Enrich(event);
        NH_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[netsh-helper] TestRegWriteSnapshotShape\n");
    {
        edr::NetshHelperDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            4205 * kSecond, "HKLM\\SOFTWARE\\Microsoft\\NetSh\\evil",
            "C:\\Temp\\evil.dll");
        detector.Enrich(event);
        NH_CHECK(Score(event) == "85");
    }
    std::fprintf(stderr, "[netsh-helper] TestShowHelperSilent\n");
    {
        edr::NetshHelperDetector detector(true, 55, 300, 1024);
        edr::Event show = ProcEvent(
            4206 * kSecond, "C:\\Windows\\System32\\netsh.exe",
            "netsh show helper");
        detector.Enrich(show);
        NH_CHECK(Score(show).empty());
        edr::Event iface = ProcEvent(
            4207 * kSecond, "C:\\Windows\\System32\\netsh.exe",
            "netsh interface ipv4 show config");
        detector.Enrich(iface);
        NH_CHECK(Score(iface).empty());
    }
    std::fprintf(stderr, "[netsh-helper] TestFirewallNotHelper\n");
    {
        edr::NetshHelperDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            4208 * kSecond, "C:\\Windows\\System32\\netsh.exe",
            "netsh advfirewall firewall add rule name=test dir=in "
            "action=allow");
        detector.Enrich(event);
        NH_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[netsh-helper] TestEmptyScriptSilent\n");
    {
        edr::NetshHelperDetector detector(true, 55, 300, 1024);
        edr::Event event = ScriptEvent(4209 * kSecond, "");
        detector.Enrich(event);
        NH_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[netsh-helper] all passed\n");
}
