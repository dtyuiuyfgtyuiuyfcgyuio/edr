/*
 * usb_exfil_detector_tests.cpp - Unit tests for UsbExfilDetector and the
 * production rule it feeds (EDR-330).
 */
#include "usb_exfil_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"
#include "usb_exfil_detector.h"

namespace {

#define UX_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "usb exfil detector test failed at line " +
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

edr::Event UsbAdded(const std::string& drive, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_USB_DEVICE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "USB_DEVICE";
    event.fields[edr::field::kUsbAction] = "added";
    event.fields[edr::field::kUsbDriveLetter] = drive;
    return event;
}

edr::Event FileCreate(const std::string& path, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_FILE_CREATE;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "FILE_CREATE";
    event.fields[edr::field::kFilePath] = path;
    return event;
}

void TestSensitiveFileSuspicious() {
    edr::UsbExfilDetector detector(true, 300, 1024, 10, 600);
    const uint64_t base = 1000000000ULL;
    detector.Enrich(UsbAdded("E:", base));
    edr::Event event = FileCreate("E:\\docs\\secrets.docx", base + 10000000ULL);
    detector.Enrich(event);
    UX_CHECK(event.fields.at(edr::field::kUsbExfilScore) == "55");
    UX_CHECK(event.fields.at(edr::field::kUsbExfilVerdict) == "SUSPICIOUS");
    UX_CHECK(event.fields.at(edr::field::kUsbExfilCount) == "1");
    UX_CHECK(event.fields.at(edr::field::kUsbExfilDrive) == "E:");
    UX_CHECK(event.fields.at(edr::field::kUsbExfilSensitive) == "true");
}

void TestBulkCopySuspicious() {
    edr::UsbExfilDetector detector(true, 300, 1024, 10, 600);
    const uint64_t base = 2000000000ULL;
    detector.Enrich(UsbAdded("F:", base));
    edr::Event stamped;
    for (uint32_t i = 1; i <= 10; ++i) {
        std::string name = "file";
        if (i < 10) name.push_back(static_cast<char>('0' + i));
        else name += "10";
        stamped = FileCreate("F:\\backup\\" + name + ".bin",
                             base + 10000000ULL * i);
        detector.Enrich(stamped);
    }
    /* Bulk copy alone: count threshold reached (+35), below the alerting
     * band and therefore without a verdict. */
    UX_CHECK(stamped.fields.at(edr::field::kUsbExfilScore) == "35");
    UX_CHECK(stamped.fields.at(edr::field::kUsbExfilCount) == "10");
    UX_CHECK(stamped.fields.at(edr::field::kUsbExfilSensitive) == "false");
    UX_CHECK(stamped.fields.find(edr::field::kUsbExfilVerdict) ==
             stamped.fields.end());
}

void TestBulkAndSensitiveMalicious() {
    edr::UsbExfilDetector detector(true, 300, 1024, 10, 0);
    const uint64_t base = 3000000000ULL;
    detector.Enrich(UsbAdded("G:", base));
    edr::Event stamped;
    for (uint32_t i = 1; i <= 10; ++i) {
        stamped = FileCreate("G:\\data\\bulk" + std::to_string(i) + ".bin",
                             base + 10000000ULL * i);
        detector.Enrich(stamped);
    }
    stamped = FileCreate("G:\\data\\plan.pdf", base + 110000000ULL);
    detector.Enrich(stamped);
    UX_CHECK(stamped.fields.at(edr::field::kUsbExfilScore) == "90");
    UX_CHECK(stamped.fields.at(edr::field::kUsbExfilVerdict) == "MALICIOUS");
    UX_CHECK(stamped.fields.at(edr::field::kUsbExfilSensitive) == "true");
}

void TestNoUsbNoStamp() {
    edr::UsbExfilDetector detector(true, 300, 1024, 10, 600);
    const uint64_t base = 4000000000ULL;
    edr::Event event = FileCreate("H:\\docs\\secrets.docx", base);
    detector.Enrich(event);
    UX_CHECK(event.fields.find(edr::field::kUsbExfilScore) ==
             event.fields.end());
}

void TestFixedDriveNoStamp() {
    edr::UsbExfilDetector detector(true, 300, 1024, 10, 600);
    const uint64_t base = 5000000000ULL;
    edr::Event event = FileCreate("C:\\Users\\me\\secrets.docx", base);
    detector.Enrich(event);
    UX_CHECK(event.fields.find(edr::field::kUsbExfilScore) ==
             event.fields.end());
}

void TestDedupSuppressesRepeat() {
    edr::UsbExfilDetector detector(true, 300, 1024, 10, 600);
    const uint64_t base = 6000000000ULL;
    detector.Enrich(UsbAdded("E:", base));
    edr::Event first = FileCreate("E:\\a.docx", base + 10000000ULL);
    detector.Enrich(first);
    UX_CHECK(first.fields.count(edr::field::kUsbExfilScore) == 1);
    edr::Event second = FileCreate("E:\\b.docx", base + 20000000ULL);
    detector.Enrich(second);
    UX_CHECK(second.fields.find(edr::field::kUsbExfilScore) ==
             second.fields.end());
}

void TestProductionRule() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        hits.push_back(alert.ruleId);
    });

    edr::UsbExfilDetector detector(true, 300, 1024, 10, 600);
    const uint64_t base = 7000000000ULL;
    detector.Enrich(UsbAdded("E:", base));
    edr::Event event = FileCreate("E:\\docs\\credentials.kdbx",
                                  base + 10000000ULL);
    detector.Enrich(event);
    engine.OnEvent(event);
    UX_CHECK(Has(hits, "EDR-330"));
}

} // namespace

void RunUsbExfilDetectorTests() {
    TestSensitiveFileSuspicious();
    TestBulkCopySuspicious();
    TestBulkAndSensitiveMalicious();
    TestNoUsbNoStamp();
    TestFixedDriveNoStamp();
    TestDedupSuppressesRepeat();
    TestProductionRule();
}
