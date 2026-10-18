/*
 * disk_wipe_detector_tests.cpp - Unit tests for DiskWipeDetector
 * (T1485 / T1561).
 */
#include "disk_wipe_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "disk_wipe_detector.h"

namespace {

#define WIPE_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "disk wipe detector test failed at line " +
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

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kDiskWipeScore) !=
           event.fields.end();
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunDiskWipeDetectorTests() {
    std::fprintf(stderr, "[disk-wipe] TestDisabled\n");
    {
        edr::DiskWipeDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "diskpart.exe", "diskpart clean all");
        detector.Enrich(event);
        WIPE_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[disk-wipe] TestDiskpartCleanAll\n");
    {
        /* diskpart clean all -> 90 malicious. */
        edr::DiskWipeDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "diskpart.exe", "diskpart clean all");
        detector.Enrich(event);
        WIPE_CHECK(HasScore(event));
        WIPE_CHECK(event.fields.at(edr::field::kDiskWipeScore) == "90");
        WIPE_CHECK(event.fields.at(edr::field::kDiskWipeVerdict) ==
                   "MALICIOUS");
        WIPE_CHECK(event.fields.at(edr::field::kDiskWipeSignals) ==
                   "diskpart_clean_all");
    }
    std::fprintf(stderr, "[disk-wipe] TestDiskpartClean\n");
    {
        /* diskpart clean (without all) -> 85 malicious. */
        edr::DiskWipeDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "diskpart.exe", "diskpart clean");
        detector.Enrich(event);
        WIPE_CHECK(event.fields.at(edr::field::kDiskWipeScore) == "85");
        WIPE_CHECK(event.fields.at(edr::field::kDiskWipeSignals) ==
                   "diskpart_clean");
    }
    std::fprintf(stderr, "[disk-wipe] TestDiskpartInspectOnly\n");
    {
        /* diskpart without a wipe action is benign. */
        edr::DiskWipeDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "diskpart.exe", "diskpart list disk");
        detector.Enrich(event);
        WIPE_CHECK(!HasScore(event));
    }
    std::fprintf(stderr, "[disk-wipe] TestQuickFormat\n");
    {
        /* format with a drive target + /q -> 75 malicious. */
        edr::DiskWipeDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "format.com", "format c: /q");
        detector.Enrich(event);
        WIPE_CHECK(event.fields.at(edr::field::kDiskWipeScore) == "75");
        WIPE_CHECK(event.fields.at(edr::field::kDiskWipeSignals) ==
                   "quick_format");
    }
    std::fprintf(stderr, "[disk-wipe] TestFullFormat\n");
    {
        /* format without /q -> 85 malicious. */
        edr::DiskWipeDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "format.com", "format d:");
        detector.Enrich(event);
        WIPE_CHECK(event.fields.at(edr::field::kDiskWipeScore) == "85");
        WIPE_CHECK(event.fields.at(edr::field::kDiskWipeSignals) ==
                   "full_format");
    }
    std::fprintf(stderr, "[disk-wipe] TestCipherWipe\n");
    {
        /* cipher /w: overwrites free space -> 60 suspicious. */
        edr::DiskWipeDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "cipher.exe", "cipher /w:C:\\");
        detector.Enrich(event);
        WIPE_CHECK(event.fields.at(edr::field::kDiskWipeScore) == "60");
        WIPE_CHECK(event.fields.at(edr::field::kDiskWipeVerdict) ==
                   "SUSPICIOUS");
        WIPE_CHECK(event.fields.at(edr::field::kDiskWipeSignals) ==
                   "cipher_free_space_wipe");
    }
    std::fprintf(stderr, "[disk-wipe] TestPowerShellVolume\n");
    {
        /* Format-Volume / Clear-Volume -> 70 suspicious. */
        edr::DiskWipeDetector detector(true, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "powershell.exe",
            "Format-Volume -DriveLetter C -Confirm:$false");
        detector.Enrich(event);
        WIPE_CHECK(event.fields.at(edr::field::kDiskWipeScore) == "70");
        WIPE_CHECK(event.fields.at(edr::field::kDiskWipeVerdict) ==
                   "SUSPICIOUS");
        WIPE_CHECK(event.fields.at(edr::field::kDiskWipeSignals) ==
                   "powershell_volume_wipe");
    }
    std::fprintf(stderr, "[disk-wipe] TestBenignSilent\n");
    {
        edr::DiskWipeDetector detector(true, 55, 300, 1024);
        edr::Event notepad = ProcEvent(
            1000 * kSecond, "notepad.exe", "notepad notes.txt");
        detector.Enrich(notepad);
        WIPE_CHECK(!HasScore(notepad));

        /* bare "format" with no drive target is not a wipe. */
        edr::Event bare = ProcEvent(
            1001 * kSecond, "format.com", "format");
        detector.Enrich(bare);
        WIPE_CHECK(!HasScore(bare));

        /* cleanmgr (disk cleanup) is not a wipe. */
        edr::Event cleanup = ProcEvent(
            1002 * kSecond, "cleanmgr.exe", "cleanmgr.exe /sagerun:1");
        detector.Enrich(cleanup);
        WIPE_CHECK(!HasScore(cleanup));
    }
    std::fprintf(stderr, "[disk-wipe] TestDedupWindow\n");
    {
        edr::DiskWipeDetector detector(true, 55, 300, 1024);
        edr::Event first = ProcEvent(
            1000 * kSecond, "diskpart.exe", "diskpart clean all");
        detector.Enrich(first);
        WIPE_CHECK(HasScore(first));
        edr::Event repeat = ProcEvent(
            1010 * kSecond, "diskpart.exe", "diskpart clean all");
        detector.Enrich(repeat);
        WIPE_CHECK(!HasScore(repeat));
        edr::Event expired = ProcEvent(
            1000 * kSecond + 301 * kSecond, "diskpart.exe",
            "diskpart clean all");
        detector.Enrich(expired);
        WIPE_CHECK(HasScore(expired));
    }
    std::fprintf(stderr, "[disk-wipe] TestInspects\n");
    {
        WIPE_CHECK(
            edr::DiskWipeDetector::Inspects(EDR_EVT_PROCESS_START));
        WIPE_CHECK(!edr::DiskWipeDetector::Inspects(EDR_EVT_REG_WRITE));
        WIPE_CHECK(!edr::DiskWipeDetector::Inspects(EDR_EVT_FILE_CREATE));
    }
    std::fprintf(stderr, "[disk-wipe] all passed\n");
}
