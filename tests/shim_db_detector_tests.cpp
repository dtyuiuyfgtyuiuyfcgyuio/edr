/*
 * shim_db_detector_tests.cpp - Unit tests for ShimDbDetector (T1546.011).
 */
#include "shim_db_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "shim_db_detector.h"

namespace {

#define SHIM_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "shim db detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcEvent(uint64_t ts100ns, const char* image,
                     const char* command) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    event.fields[edr::field::kImage] = image;
    if (command != nullptr) {
        event.fields[edr::field::kCommandLine] = command;
    }
    return event;
}

edr::Event RegEvent(uint64_t ts100ns, const char* regKey) {
    edr::Event event;
    event.type = EDR_EVT_REG_WRITE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "REG_WRITE";
    event.fields[edr::field::kRegKey] = regKey;
    return event;
}

edr::Event FileEvent(uint64_t ts100ns, const char* filePath) {
    edr::Event event;
    event.type = EDR_EVT_FILE_CREATE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "FILE_CREATE";
    event.fields[edr::field::kFilePath] = filePath;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kShimDbScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunShimDbDetectorTests() {
    std::fprintf(stderr, "[shim-db] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::ShimDbDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "sdbinst.exe",
            "sdbinst.exe C:\\Users\\a\\payload.sdb");
        detector.Enrich(event);
        SHIM_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[shim-db] TestSdbinstInstall\n");
    {
        /* Installing a .sdb shim -> 85 malicious. */
        edr::ShimDbDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "sdbinst.exe",
            "sdbinst.exe -q C:\\Users\\a\\payload.sdb");
        detector.Enrich(event);
        SHIM_CHECK(HasScore(event));
        SHIM_CHECK(event.fields.at(edr::field::kShimDbScore) == "85");
        SHIM_CHECK(event.fields.at(edr::field::kShimDbVerdict) ==
                   "MALICIOUS");
        SHIM_CHECK(event.fields.at(edr::field::kShimDbSignals).find(
                       "sdbinst") != std::string::npos);
    }
    std::fprintf(stderr, "[shim-db] TestSdbinstUninstallIgnored\n");
    {
        /* Uninstalling (-u) is cleanup, not persistence. */
        edr::ShimDbDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "sdbinst.exe", "sdbinst.exe -u payload.sdb");
        detector.Enrich(event);
        SHIM_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[shim-db] TestCustomShimRegWrite\n");
    {
        /* AppCompatFlags\Custom write -> 90 malicious. */
        edr::ShimDbDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            1000 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
            "AppCompatFlags\\Custom\\svchost.exe");
        detector.Enrich(event);
        SHIM_CHECK(event.fields.at(edr::field::kShimDbScore) == "90");
        SHIM_CHECK(event.fields.at(edr::field::kShimDbVerdict) ==
                   "MALICIOUS");
        SHIM_CHECK(event.fields.at(edr::field::kShimDbSignals).find(
                       "custom") != std::string::npos);
    }
    std::fprintf(stderr, "[shim-db] TestInstallsdbRegWrite\n");
    {
        /* InstalledSDB write -> 80 malicious. */
        edr::ShimDbDetector detector(true, 55, 300, 1024);
        edr::Event event = RegEvent(
            1000 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
            "AppCompatFlags\\InstalledSDB\\{guid}");
        detector.Enrich(event);
        SHIM_CHECK(event.fields.at(edr::field::kShimDbScore) == "80");
    }
    std::fprintf(stderr, "[shim-db] TestStagedSdbFile\n");
    {
        /* .sdb dropped in a user-writable path -> 55 suspicious. */
        edr::ShimDbDetector detector(true, 55, 300, 1024);
        edr::Event event = FileEvent(
            1000 * kSecond, "C:\\Users\\a\\AppData\\Local\\Temp\\x.sdb");
        detector.Enrich(event);
        SHIM_CHECK(event.fields.at(edr::field::kShimDbScore) == "55");
        SHIM_CHECK(event.fields.at(edr::field::kShimDbVerdict) ==
                   "SUSPICIOUS");
        SHIM_CHECK(event.fields.at(edr::field::kShimDbPaths).find(
                       ".sdb") != std::string::npos);
    }
    std::fprintf(stderr, "[shim-db] TestSystemSdbIgnored\n");
    {
        /* .sdb in a system path is not user-staged. */
        edr::ShimDbDetector detector(true, 55, 300, 1024);
        edr::Event event = FileEvent(
            1000 * kSecond, "C:\\Windows\\System32\\sysmain.sdb");
        detector.Enrich(event);
        SHIM_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[shim-db] TestBenignSilent\n");
    {
        edr::ShimDbDetector detector(true, 55, 300, 1024);
        edr::Event notepad = ProcEvent(
            1000 * kSecond, "notepad.exe", "notepad notes.txt");
        detector.Enrich(notepad);
        SHIM_CHECK(!HasScore(notepad));

        /* AppCompatFlags key without Custom/InstalledSDB subkey. */
        edr::Event reg = RegEvent(
            1001 * kSecond,
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
            "AppCompatFlags\\Layers\\foo.exe");
        detector.Enrich(reg);
        SHIM_CHECK(!HasScore(reg));
    }
    std::fprintf(stderr, "[shim-db] TestDedupWindow\n");
    {
        edr::ShimDbDetector detector(true, 55, 300, 1024);
        edr::Event first = ProcEvent(
            1000 * kSecond, "sdbinst.exe",
            "sdbinst.exe C:\\x.sdb");
        detector.Enrich(first);
        SHIM_CHECK(HasScore(first));
        edr::Event repeat = ProcEvent(
            1010 * kSecond, "sdbinst.exe",
            "sdbinst.exe C:\\x.sdb");
        detector.Enrich(repeat);
        SHIM_CHECK(!HasScore(repeat));
        edr::Event expired = ProcEvent(
            1000 * kSecond + 301 * kSecond, "sdbinst.exe",
            "sdbinst.exe C:\\x.sdb");
        detector.Enrich(expired);
        SHIM_CHECK(HasScore(expired));
    }
    std::fprintf(stderr, "[shim-db] TestInspects\n");
    {
        SHIM_CHECK(
            edr::ShimDbDetector::Inspects(EDR_EVT_PROCESS_START));
        SHIM_CHECK(edr::ShimDbDetector::Inspects(EDR_EVT_REG_WRITE));
        SHIM_CHECK(edr::ShimDbDetector::Inspects(EDR_EVT_FILE_CREATE));
        SHIM_CHECK(!edr::ShimDbDetector::Inspects(EDR_EVT_DNS_QUERY));
    }
    std::fprintf(stderr, "[shim-db] all passed\n");
}
