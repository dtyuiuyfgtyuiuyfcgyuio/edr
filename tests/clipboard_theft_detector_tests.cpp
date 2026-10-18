/* Unit tests for ClipboardTheftDetector. */
#include "clipboard_theft_detector_tests.h"

#include <cstdio>
#include <stdexcept>
#include <string>

#include "clipboard_theft_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error("clipboard theft detector test failed at line " +
                                 std::to_string(line) + ": " + expression);
}
#define CT_CHECK(c) Check((c), #c, __LINE__)

edr::Event Clipboard(uint64_t ts, uint32_t pid, const char* image,
                     const char* format = "13") {
    edr::Event event;
    event.type = EDR_EVT_CLIPBOARD_ACCESS;
    event.ts100ns = ts;
    event.pid = pid;
    event.fields[edr::field::kType] = "CLIPBOARD_ACCESS";
    event.fields[edr::field::kPid] = std::to_string(pid);
    event.fields[edr::field::kImage] = image;
    event.fields[edr::field::kClipboardFormat] = format;
    return event;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunClipboardTheftDetectorTests() {
    std::fprintf(stderr, "[clipboard-theft] TestDisabled\n");
    {
        edr::ClipboardTheftDetector detector(false, 55, 120, 32, 3, 60);
        auto event = Clipboard(kSecond, 100, "C:\\Tools\\stealer.exe");
        detector.Enrich(event);
        CT_CHECK(event.fields.find(edr::field::kClipboardTheftScore) ==
                 event.fields.end());
    }

    std::fprintf(stderr, "[clipboard-theft] TestCollectorTool\n");
    {
        edr::ClipboardTheftDetector detector(true, 55, 120, 32, 3, 60);
        auto event = Clipboard(kSecond, 100, "C:\\Tools\\stealer.exe");
        detector.Enrich(event);
        CT_CHECK(event.fields.at(edr::field::kClipboardTheftVerdict) ==
                 "malicious");
        CT_CHECK(event.fields.at(edr::field::kClipboardTheftSignals).find(
                     "collection_tool_image") != std::string::npos);
    }

    std::fprintf(stderr, "[clipboard-theft] TestRepeatedReads\n");
    {
        edr::ClipboardTheftDetector detector(true, 55, 120, 32, 3, 60);
        auto first = Clipboard(kSecond, 101, "C:\\Tools\\unknown.exe");
        detector.Enrich(first);
        CT_CHECK(first.fields.find(edr::field::kClipboardTheftScore) ==
                 first.fields.end());
        auto second = Clipboard(2 * kSecond, 101, "C:\\Tools\\unknown.exe");
        detector.Enrich(second);
        auto third = Clipboard(3 * kSecond, 101, "C:\\Tools\\unknown.exe");
        detector.Enrich(third);
        CT_CHECK(third.fields.at(edr::field::kClipboardTheftSignals).find(
                     "repeated_text_reads") != std::string::npos);
        CT_CHECK(third.fields.at(edr::field::kClipboardTheftTextReadCount) ==
                 "3");
    }

    std::fprintf(stderr, "[clipboard-theft] TestRoutineReaderAndDedup\n");
    {
        edr::ClipboardTheftDetector detector(true, 55, 120, 32, 3, 60);
        for (int i = 0; i < 3; ++i) {
            auto event = Clipboard((i + 1) * kSecond, 102,
                                   "C:\\Windows\\explorer.exe");
            detector.Enrich(event);
            CT_CHECK(event.fields.find(edr::field::kClipboardTheftScore) ==
                     event.fields.end());
        }
    }

    std::fprintf(stderr, "[clipboard-theft] TestExpiryAndCapacity\n");
    {
        edr::ClipboardTheftDetector detector(true, 55, 10, 2, 2, 60);
        for (int i = 0; i < 5; ++i) {
            auto event = Clipboard((i + 1) * kSecond, 200 + i,
                                   "C:\\Tools\\unknown.exe");
            detector.Enrich(event);
        }
        CT_CHECK(detector.StateCount() <= 2);
        auto expired = Clipboard(30 * kSecond, 204,
                                 "C:\\Tools\\unknown.exe");
        detector.Enrich(expired);
        CT_CHECK(expired.fields.find(edr::field::kClipboardTheftScore) ==
                 expired.fields.end());
    }
    std::fprintf(stderr, "[clipboard-theft] all passed\n");
}
