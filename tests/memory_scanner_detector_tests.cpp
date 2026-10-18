/*
 * memory_scanner_detector_tests.cpp - Unit tests for
 * MemoryScannerDetector.
 */
#include "memory_scanner_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "memory_scanner_detector.h"

namespace {

#define MS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "memory scanner detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcessAccess(uint32_t pid, uint32_t targetPid, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_ACCESS;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.fields[edr::field::kType] = "PROCESS_ACCESS";
    event.fields[edr::field::kTargetPid] = std::to_string(targetPid);
    event.fields[edr::field::kTargetImage] = "lsass.exe";
    return event;
}

edr::Event ThreadCreate(uint32_t pid, uint32_t targetPid, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_THREAD_CREATE;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.fields[edr::field::kType] = "THREAD_CREATE";
    event.fields[edr::field::kTargetPid] = std::to_string(targetPid);
    event.fields[edr::field::kTargetImage] = "explorer.exe";
    event.fields[edr::field::kRemoteThread] = "true";
    return event;
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

bool HasScanFields(const edr::Event& event) {
    return HasField(event, edr::field::kMemoryScanScore) &&
           HasField(event, edr::field::kMemoryScanReasons);
}

bool HasNoScanFields(const edr::Event& event) {
    return !HasField(event, edr::field::kMemoryScanScore) &&
           !HasField(event, edr::field::kMemoryScanReasons);
}

void TestDisabled() {
    edr::MemoryScannerDetector detector(false, 55, 60, 2048);
    edr::Event event = ProcessAccess(1234, 888, 100000000000ULL);
    detector.Enrich(event);
    MS_CHECK(HasNoScanFields(event));
    MS_CHECK(detector.StateCount() == 0);
}

void TestFullAccessComboToLsass() {
    /* Full VM_READ+VM_WRITE+VM_OPERATION+CREATE_THREAD combo to lsass is
     * the highest-severity single-event signal: 45 points, plus 15 for
     * targeting a critical process = 60. */
    edr::MemoryScannerDetector detector(true, 55, 60, 2048);
    edr::Event event = ProcessAccess(1234, 888, 100000000000ULL);
    event.fields[edr::field::kAccessVmRead] = "1";
    event.fields[edr::field::kAccessVmWrite] = "1";
    event.fields[edr::field::kAccessVmOperation] = "1";
    event.fields[edr::field::kAccessCreateThread] = "1";
    detector.Enrich(event);
    MS_CHECK(HasScanFields(event));
    MS_CHECK(event.fields.at(edr::field::kMemoryScanScore) == "60");
    MS_CHECK(event.fields.at(edr::field::kMemoryScanReasons).find(
        "full_memory_access_combo") != std::string::npos);
    MS_CHECK(detector.StateCount() == 1);
}

void TestRemoteThreadToUnmapped() {
    /* Remote thread into a non-module address: high suspicion. */
    edr::MemoryScannerDetector detector(true, 55, 60, 2048);
    edr::Event event = ThreadCreate(1234, 777, 100000000000ULL);
    event.fields[edr::field::kStartModule] = "unknown";
    detector.Enrich(event);
    MS_CHECK(HasScanFields(event));
    MS_CHECK(event.fields.at(edr::field::kMemoryScanScore) == "65");
    MS_CHECK(detector.StateCount() == 1);
}

void TestSelfAccessNotStamped() {
    /* Process reading itself is normal: no score. */
    edr::MemoryScannerDetector detector(true, 55, 60, 2048);
    edr::Event event = ProcessAccess(1234, 1234, 100000000000ULL);
    detector.Enrich(event);
    MS_CHECK(HasNoScanFields(event));
    MS_CHECK(detector.StateCount() == 1);
}

void TestInspectsTypes() {
    MS_CHECK(edr::MemoryScannerDetector::Inspects(EDR_EVT_PROCESS_ACCESS));
    MS_CHECK(edr::MemoryScannerDetector::Inspects(EDR_EVT_THREAD_CREATE));
    MS_CHECK(edr::MemoryScannerDetector::Inspects(EDR_EVT_MEMORY_WRITE));
    MS_CHECK(edr::MemoryScannerDetector::Inspects(EDR_EVT_IMAGE_LOAD));
    MS_CHECK(edr::MemoryScannerDetector::Inspects(EDR_EVT_PROCESS_START));
    MS_CHECK(!edr::MemoryScannerDetector::Inspects(EDR_EVT_REG_WRITE));
}

} // namespace

void RunMemoryScannerDetectorTests() {
    TestDisabled();
    TestFullAccessComboToLsass();
    TestRemoteThreadToUnmapped();
    TestSelfAccessNotStamped();
    TestInspectsTypes();
}