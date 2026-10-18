/*
 * hidden_artifacts_detector_tests.cpp - Unit tests for
 * HiddenArtifactsDetector.
 */
#include "hidden_artifacts_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "hidden_artifacts_detector.h"

namespace {

#define CHECK_HA(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "hidden artifacts detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcessStart(uint32_t pid, const char* image,
                        const char* commandLine, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.pid = pid;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

edr::Event FileCreate(uint32_t pid, const char* image,
                      const char* filePath, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_FILE_CREATE;
    event.pid = pid;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "FILE_CREATE";
    event.fields[edr::field::kImage] = image;
    event.fields[edr::field::kFilePath] = filePath;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kHiddenArtifactsScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunHiddenArtifactsDetectorTests() {
    std::fprintf(stderr, "[hidden-artifacts] TestDisabled\n");
    {
        edr::HiddenArtifactsDetector detector(false, 300, 2048);
        edr::Event event = ProcessStart(
            9001, "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c echo payload > C:\\Temp\\note.txt:hidden",
            1000 * kSecond);
        detector.Enrich(event);
        CHECK_HA(!HasScore(event));
    }
    std::fprintf(stderr, "[hidden-artifacts] TestAdsCommandLine\n");
    {
        edr::HiddenArtifactsDetector detector(true, 300, 2048);
        edr::Event event = ProcessStart(
            9002, "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c echo payload > C:\\Temp\\note.txt:hidden",
            1000 * kSecond);
        detector.Enrich(event);
        CHECK_HA(HasScore(event));
        CHECK_HA(event.fields.at(edr::field::kHiddenArtifactsScore) == "55");
        CHECK_HA(event.fields.at(edr::field::kHiddenArtifactsVerdict) ==
                 "SUSPICIOUS");
        CHECK_HA(event.fields.at(edr::field::kHiddenArtifactsSignals)
                     .find("ads_write") != std::string::npos);
    }
    std::fprintf(stderr, "[hidden-artifacts] TestInterpreterAds\n");
    {
        edr::HiddenArtifactsDetector detector(true, 300, 2048);
        edr::Event event = ProcessStart(
            9003, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
                  "powershell.exe",
            "powershell.exe -c Set-Content -Path C:\\Temp\\log.txt:s "
            "-Value base64blob",
            1000 * kSecond);
        detector.Enrich(event);
        CHECK_HA(HasScore(event));
        CHECK_HA(event.fields.at(edr::field::kHiddenArtifactsScore) == "90");
        CHECK_HA(event.fields.at(edr::field::kHiddenArtifactsVerdict) ==
                 "MALICIOUS");
        CHECK_HA(event.fields.at(edr::field::kHiddenArtifactsSignals)
                     .find("interpreter_ads") != std::string::npos);
    }
    std::fprintf(stderr, "[hidden-artifacts] TestHiddenAttribCommand\n");
    {
        edr::HiddenArtifactsDetector detector(true, 300, 2048);
        edr::Event event = ProcessStart(
            9004, "C:\\Windows\\System32\\attrib.exe",
            "attrib +h C:\\Users\\Public\\drop\\payload.exe",
            1000 * kSecond);
        detector.Enrich(event);
        CHECK_HA(HasScore(event));
        /* hidden_attrib(45) + executable(25) + user-writable(10) = 80. */
        CHECK_HA(event.fields.at(edr::field::kHiddenArtifactsScore) == "80");
        CHECK_HA(event.fields.at(edr::field::kHiddenArtifactsVerdict) ==
                 "MALICIOUS");
    }
    std::fprintf(stderr, "[hidden-artifacts] TestCreateThenHide\n");
    {
        edr::HiddenArtifactsDetector detector(true, 300, 2048);
        edr::Event create = FileCreate(
            9005, "C:\\Temp\\implant.exe",
            "C:\\Users\\Public\\Downloads\\update.exe", 1000 * kSecond);
        detector.Enrich(create);
        CHECK_HA(!HasScore(create));
        edr::Event hide = ProcessStart(
            9005, "C:\\Windows\\System32\\attrib.exe",
            "attrib +h C:\\Users\\Public\\Downloads\\update.exe",
            1010 * kSecond);
        detector.Enrich(hide);
        CHECK_HA(HasScore(hide));
        /* hidden_attrib(45) + create_then_hide(35) + executable(25)
         * + user-writable(10) = 115 -> capped at 100. */
        CHECK_HA(hide.fields.at(edr::field::kHiddenArtifactsScore) == "100");
        CHECK_HA(hide.fields.at(edr::field::kHiddenArtifactsSignals)
                     .find("hidden_attrib") != std::string::npos);
    }
    std::fprintf(stderr, "[hidden-artifacts] TestAdsFileCreateEvent\n");
    {
        edr::HiddenArtifactsDetector detector(true, 300, 2048);
        edr::Event event = FileCreate(
            9006, "C:\\Temp\\tool.exe",
            "C:\\Users\\bob\\AppData\\Local\\Temp\\readme.txt:Zone.Identifier",
            1000 * kSecond);
        detector.Enrich(event);
        CHECK_HA(HasScore(event));
        CHECK_HA(event.fields.at(edr::field::kHiddenArtifactsScore) == "55");
        CHECK_HA(event.fields.at(edr::field::kHiddenArtifactsAdsPaths)
                     .find("readme.txt:Zone.Identifier") !=
                 std::string::npos);
    }
    std::fprintf(stderr, "[hidden-artifacts] TestNormalFileIgnored\n");
    {
        edr::HiddenArtifactsDetector detector(true, 300, 2048);
        edr::Event event = FileCreate(
            9007, "C:\\Temp\\tool.exe",
            "C:\\Users\\bob\\Documents\\report.docx", 1000 * kSecond);
        detector.Enrich(event);
        CHECK_HA(!HasScore(event));
    }
    std::fprintf(stderr, "[hidden-artifacts] TestNormalCommandIgnored\n");
    {
        edr::HiddenArtifactsDetector detector(true, 300, 2048);
        edr::Event event = ProcessStart(
            9008, "C:\\Windows\\System32\\netstat.exe",
            "netstat.exe -an", 1000 * kSecond);
        detector.Enrich(event);
        CHECK_HA(!HasScore(event));
    }
    std::fprintf(stderr, "[hidden-artifacts] All tests passed\n");
}
