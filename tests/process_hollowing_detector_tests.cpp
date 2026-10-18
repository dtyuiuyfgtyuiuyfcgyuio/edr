/*
 * process_hollowing_detector_tests.cpp - Unit tests for
 * ProcessHollowingDetector.
 */
#include "process_hollowing_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "process_hollowing_detector.h"

namespace {

#define PH_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "process hollowing detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcessStart(uint32_t pid, const char* image,
                        const char* parentImage, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.fields[edr::field::kType] = "PROCESS_START";
    if (image) event.fields[edr::field::kImage] = image;
    if (parentImage) event.fields[edr::field::kParentImage] = parentImage;
    return event;
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

bool HasAllHollowFields(const edr::Event& event) {
    return HasField(event, edr::field::kHollowScore) &&
           HasField(event, edr::field::kHollowReasons) &&
           HasField(event, edr::field::kHollowBase) &&
           HasField(event, edr::field::kHollowPath) &&
           HasField(event, edr::field::kHollowParent);
}

bool HasNoHollowFields(const edr::Event& event) {
    return !HasField(event, edr::field::kHollowScore) &&
           !HasField(event, edr::field::kHollowReasons) &&
           !HasField(event, edr::field::kHollowBase) &&
           !HasField(event, edr::field::kHollowPath) &&
           !HasField(event, edr::field::kHollowParent);
}

void TestDisabled() {
    edr::ProcessHollowingDetector detector(false, 55, 30, 1024);
    edr::Event event = ProcessStart(
        1234, "c:\\users\\alice\\svchost.exe", nullptr, 100000000000ULL);
    detector.Enrich(event);
    PH_CHECK(HasNoHollowFields(event));
    PH_CHECK(detector.StateCount() == 0);
}

void TestBasenameOnlyImageSkipped() {
    edr::ProcessHollowingDetector detector(true, 55, 30, 1024);
    /* Process polling reports basename-only images; they must be skipped so
     * the poll source cannot false-positive. */
    edr::Event event = ProcessStart(1234, "svchost.exe", nullptr,
                                    100000000000ULL);
    detector.Enrich(event);
    PH_CHECK(HasNoHollowFields(event));
    PH_CHECK(detector.StateCount() == 0);

    /* pid 0 events are ignored as well. */
    edr::Event zeroPid = ProcessStart(0, "c:\\users\\alice\\svchost.exe",
                                      nullptr, 100000000000ULL);
    detector.Enrich(zeroPid);
    PH_CHECK(HasNoHollowFields(zeroPid));
    PH_CHECK(detector.StateCount() == 0);
}

void TestSystemDirectoryNotStamped() {
    edr::ProcessHollowingDetector detector(true, 55, 30, 1024);
    edr::Event event = ProcessStart(
        1234, "c:\\windows\\system32\\svchost.exe", nullptr, 100000000000ULL);
    detector.Enrich(event);
    PH_CHECK(HasNoHollowFields(event));
    PH_CHECK(detector.StateCount() == 0);
}

void TestStagingPathScoresEighty() {
    edr::ProcessHollowingDetector detector(true, 55, 30, 1024);
    const char* image = "c:\\users\\alice\\appdata\\local\\temp\\svchost.exe";
    edr::Event event = ProcessStart(1234, image, nullptr, 100000000000ULL);
    detector.Enrich(event);
    PH_CHECK(HasAllHollowFields(event));
    PH_CHECK(event.fields.at(edr::field::kHollowScore) == "80");
    PH_CHECK(event.fields.at(edr::field::kHollowReasons) ==
             "outside_system_dir,user_writable_path");
    PH_CHECK(event.fields.at(edr::field::kHollowBase) == "svchost.exe");
    PH_CHECK(event.fields.at(edr::field::kHollowPath) == image);
    PH_CHECK(event.fields.at(edr::field::kHollowParent).empty());
    PH_CHECK(detector.StateCount() == 1);
}

void TestOutsideSystemDirScoresFiftyFive() {
    edr::ProcessHollowingDetector detector(true, 55, 30, 1024);
    edr::Event event = ProcessStart(1234, "c:\\users\\alice\\svchost.exe",
                                    nullptr, 100000000000ULL);
    detector.Enrich(event);
    PH_CHECK(HasAllHollowFields(event));
    PH_CHECK(event.fields.at(edr::field::kHollowScore) == "55");
    PH_CHECK(event.fields.at(edr::field::kHollowReasons) ==
             "outside_system_dir");
    PH_CHECK(detector.StateCount() == 1);
}

void TestUnusualParentBoostsToSeventyFive() {
    edr::ProcessHollowingDetector detector(true, 55, 30, 1024);
    edr::Event event = ProcessStart(
        1234, "c:\\users\\alice\\svchost.exe",
        "c:\\program files\\microsoft office\\root\\office16\\winword.exe",
        100000000000ULL);
    detector.Enrich(event);
    PH_CHECK(HasAllHollowFields(event));
    PH_CHECK(event.fields.at(edr::field::kHollowScore) == "75");
    PH_CHECK(event.fields.at(edr::field::kHollowReasons) ==
             "outside_system_dir,unusual_parent");
    PH_CHECK(event.fields.at(edr::field::kHollowParent) == "winword.exe");
    PH_CHECK(detector.StateCount() == 1);
}

void TestNonProtectedNameSkipped() {
    edr::ProcessHollowingDetector detector(true, 55, 30, 1024);
    edr::Event event = ProcessStart(1234, "c:\\users\\alice\\notepad.exe",
                                    nullptr, 100000000000ULL);
    detector.Enrich(event);
    PH_CHECK(HasNoHollowFields(event));
    PH_CHECK(detector.StateCount() == 0);
}

void TestDedupWindow() {
    edr::ProcessHollowingDetector detector(true, 55, 30, 1024);
    const uint64_t base = 100000000000ULL;
    const char* image = "c:\\users\\alice\\svchost.exe";

    edr::Event first = ProcessStart(1234, image, nullptr, base);
    detector.Enrich(first);
    PH_CHECK(HasAllHollowFields(first));
    PH_CHECK(detector.StateCount() == 1);

    /* Same pid@path within the 30s window: nothing is stamped again. */
    edr::Event dup = ProcessStart(1234, image, nullptr, base + 10000000ULL);
    detector.Enrich(dup);
    PH_CHECK(HasNoHollowFields(dup));
    PH_CHECK(detector.StateCount() == 1);

    /* Beyond the window the entry has expired: the event stamps again. */
    edr::Event later =
        ProcessStart(1234, image, nullptr, base + 400000000ULL);
    detector.Enrich(later);
    PH_CHECK(HasAllHollowFields(later));
    PH_CHECK(later.fields.at(edr::field::kHollowScore) == "55");
    PH_CHECK(detector.StateCount() == 1);
}

void TestCapacityEviction() {
    edr::ProcessHollowingDetector detector(true, 55, 30, 2);
    const uint64_t base = 100000000000ULL;
    for (uint32_t pid = 1; pid <= 5; ++pid) {
        edr::Event event = ProcessStart(pid, "c:\\users\\alice\\svchost.exe",
                                        nullptr, base + pid * 1000000ULL);
        detector.Enrich(event);
        PH_CHECK(HasAllHollowFields(event));
    }
    PH_CHECK(detector.StateCount() <= 2);
}

void TestForwardSlashSystemPathNotStamped() {
    edr::ProcessHollowingDetector detector(true, 55, 30, 1024);
    edr::Event event = ProcessStart(1234, "C:/Windows/System32/svchost.exe",
                                    nullptr, 100000000000ULL);
    detector.Enrich(event);
    PH_CHECK(HasNoHollowFields(event));
    PH_CHECK(detector.StateCount() == 0);
}

} // namespace

void RunProcessHollowingDetectorTests() {
    TestDisabled();
    TestBasenameOnlyImageSkipped();
    TestSystemDirectoryNotStamped();
    TestStagingPathScoresEighty();
    TestOutsideSystemDirScoresFiftyFive();
    TestUnusualParentBoostsToSeventyFive();
    TestNonProtectedNameSkipped();
    TestDedupWindow();
    TestCapacityEviction();
    TestForwardSlashSystemPathNotStamped();
}
