/*
 * ransom_burst_detector_tests.cpp - Unit tests for RansomBurstDetector.
 */
#include "ransom_burst_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "ransom_burst_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define RANSOM_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "ransom burst detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event FileCreate(uint32_t pid, const char* image, const char* filePath,
                      uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_FILE_CREATE;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.fields[edr::field::kType] = "FILE_CREATE";
    if (image) event.fields[edr::field::kImage] = image;
    if (filePath) event.fields[edr::field::kFilePath] = filePath;
    return event;
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

size_t CountCommaSeparated(const std::string& value) {
    if (value.empty()) return 0;
    size_t count = 1;
    for (char c : value) {
        if (c == ',') ++count;
    }
    return count;
}

/* V1: pid-attribution keying. 10 FILE_CREATE events for one pid/image with
 * exactly 5 distinct extensions reach the threshold on the 10th event. */
void TestPidAttributionFlagged() {
    edr::RansomBurstDetector detector(true, 60, 8192, 10, 5);
    const uint64_t base = 100000000000ULL;
    const char* image = "C:\\evil\\encryptor.exe";
    const char* extensions[] = {"docx", "pdf", "xlsx", "jpg", "png"};

    edr::Event last;
    for (int i = 0; i < 10; ++i) {
        std::string path = "C:\\Users\\victim\\Documents\\file" +
                           std::to_string(i) + "." +
                           extensions[i % 5];
        last = FileCreate(1001, image, path.c_str(), base + i * 1000000);
        detector.Enrich(last);
    }
    RANSOM_CHECK(HasField(last, edr::field::kRansomBurstScore));
    RANSOM_CHECK(last.fields.at(edr::field::kRansomBurstScore) == "10");
    RANSOM_CHECK(last.fields.at(edr::field::kRansomBurstCount) == "10");
    RANSOM_CHECK(CountCommaSeparated(
                     last.fields.at(edr::field::kRansomBurstExtensions)) == 5);
    RANSOM_CHECK(last.fields.at(edr::field::kRansomBurstWindowSeconds) == "60");
    RANSOM_CHECK(detector.StateCount() == 1);
}

/* V2: directory fallback for pid==0 events, keyed on the lowercased
 * directory of file_path. */
void TestDirectoryFallbackFlagged() {
    edr::RansomBurstDetector detector(true, 60, 8192, 10, 5);
    const uint64_t base = 200000000000ULL;
    const char* extensions[] = {"docx", "pdf", "xlsx", "jpg", "png"};

    edr::Event last;
    for (int i = 0; i < 10; ++i) {
        std::string path = "C:\\Users\\Public\\Documents\\doc" +
                           std::to_string(i) + "." +
                           extensions[i % 5];
        last = FileCreate(0, nullptr, path.c_str(), base + i * 1000000);
        detector.Enrich(last);
    }
    RANSOM_CHECK(HasField(last, edr::field::kRansomBurstScore));
    RANSOM_CHECK(last.fields.at(edr::field::kRansomBurstScore) == "10");
    RANSOM_CHECK(last.fields.at(edr::field::kRansomBurstCount) == "10");
    RANSOM_CHECK(CountCommaSeparated(
                     last.fields.at(edr::field::kRansomBurstExtensions)) == 5);
    RANSOM_CHECK(last.fields.at(edr::field::kRansomBurstWindowSeconds) == "60");
    RANSOM_CHECK(detector.StateCount() == 1);
}

/* V3: no attribution (pid==0 and no file_path) is skipped entirely. */
void TestNoAttribution() {
    edr::RansomBurstDetector detector(true, 60, 8192, 10, 5);
    edr::Event event = FileCreate(0, nullptr, nullptr, 1000);
    detector.Enrich(event);
    RANSOM_CHECK(!HasField(event, edr::field::kRansomBurstScore));
    RANSOM_CHECK(!HasField(event, edr::field::kRansomBurstCount));
    RANSOM_CHECK(!HasField(event, edr::field::kRansomBurstExtensions));
    RANSOM_CHECK(!HasField(event, edr::field::kRansomBurstWindowSeconds));
    RANSOM_CHECK(detector.StateCount() == 0);
}

/* V4: window expiry drops the key and resets the flag; fields are re-emitted
 * only once the threshold is met again. */
void TestWindowExpiry() {
    edr::RansomBurstDetector detector(true, 60, 8192, 3, 2);
    const uint64_t base = 300000000000ULL;
    const char* image = "C:\\evil\\encryptor.exe";

    /* Build up to a flagged state (3 files, 2 distinct extensions). */
    edr::Event a =
        FileCreate(1001, image, "C:\\evil\\out1.docx", base);
    detector.Enrich(a);
    edr::Event b =
        FileCreate(1001, image, "C:\\evil\\out2.pdf", base + 1000000);
    detector.Enrich(b);
    edr::Event c =
        FileCreate(1001, image, "C:\\evil\\out3.docx", base + 2000000);
    detector.Enrich(c);
    RANSOM_CHECK(HasField(c, edr::field::kRansomBurstScore));
    RANSOM_CHECK(c.fields.at(edr::field::kRansomBurstScore) == "3");
    RANSOM_CHECK(c.fields.at(edr::field::kRansomBurstCount) == "3");
    RANSOM_CHECK(detector.StateCount() == 1);

    /* Advance beyond the 60s window: the key expires, is dropped, and the
     * flag resets. The single re-feed recreates the key without fields. */
    edr::Event d =
        FileCreate(1001, image, "C:\\evil\\out4.docx", base + 700000000ULL);
    detector.Enrich(d);
    RANSOM_CHECK(!HasField(d, edr::field::kRansomBurstScore));
    RANSOM_CHECK(detector.StateCount() == 1);

    /* Rebuild the threshold: fields are emitted again only once 3 files show
     * >= 2 distinct extensions. */
    edr::Event d2 =
        FileCreate(1001, image, "C:\\evil\\out5.pdf", base + 710000000ULL);
    detector.Enrich(d2);
    RANSOM_CHECK(!HasField(d2, edr::field::kRansomBurstScore));
    edr::Event d3 =
        FileCreate(1001, image, "C:\\evil\\out6.docx", base + 720000000ULL);
    detector.Enrich(d3);
    RANSOM_CHECK(HasField(d3, edr::field::kRansomBurstScore));
    RANSOM_CHECK(d3.fields.at(edr::field::kRansomBurstScore) == "3");
    RANSOM_CHECK(d3.fields.at(edr::field::kRansomBurstCount) == "3");
}

/* V5: disabled detector is a no-op. */
void TestDisabled() {
    edr::RansomBurstDetector detector(false, 60, 8192, 10, 5);
    edr::Event event = FileCreate(1001, "C:\\evil\\encryptor.exe",
                                  "C:\\evil\\a.docx", 1000);
    detector.Enrich(event);
    RANSOM_CHECK(!HasField(event, edr::field::kRansomBurstScore));
    RANSOM_CHECK(!HasField(event, edr::field::kRansomBurstCount));
    RANSOM_CHECK(!HasField(event, edr::field::kRansomBurstExtensions));
    RANSOM_CHECK(!HasField(event, edr::field::kRansomBurstWindowSeconds));
    RANSOM_CHECK(detector.StateCount() == 0);
}

/* V6: capacity eviction bounds state at stateCapacity keys. */
void TestCapacityEviction() {
    edr::RansomBurstDetector detector(true, 60, 2, 10, 5);
    const uint64_t base = 500000000000ULL;
    for (uint32_t pid = 1; pid <= 3; ++pid) {
        edr::Event event = FileCreate(pid, "C:\\evil\\encryptor.exe",
                                      "C:\\evil\\a.docx",
                                      base + pid * 1000000);
        detector.Enrich(event);
    }
    RANSOM_CHECK(detector.StateCount() <= 2);
}

void TestInspects() {
    RANSOM_CHECK(edr::RansomBurstDetector::Inspects(EDR_EVT_FILE_CREATE));
    RANSOM_CHECK(!edr::RansomBurstDetector::Inspects(EDR_EVT_NET_CONNECT));
    RANSOM_CHECK(!edr::RansomBurstDetector::Inspects(EDR_EVT_PROCESS_START));
}

} // namespace

void RunRansomBurstDetectorTests() {
    std::printf("[ransom] TestPidAttributionFlagged\n");
    TestPidAttributionFlagged();
    std::printf("[ransom] TestDirectoryFallbackFlagged\n");
    TestDirectoryFallbackFlagged();
    std::printf("[ransom] TestNoAttribution\n");
    TestNoAttribution();
    std::printf("[ransom] TestWindowExpiry\n");
    TestWindowExpiry();
    std::printf("[ransom] TestDisabled\n");
    TestDisabled();
    std::printf("[ransom] TestCapacityEviction\n");
    TestCapacityEviction();
    std::printf("[ransom] TestInspects\n");
    TestInspects();
    std::printf("[ransom] all passed\n");
}