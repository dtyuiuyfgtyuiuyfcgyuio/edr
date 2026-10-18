/*
 * share_change_detector_tests.cpp - Unit tests for ShareChangeDetector
 * (T1021.002 / T1070.005).
 *
 * The detector consumes SHARE_CHANGE events from the share monitor
 * collector and scores each change independently (no dedup state).
 * Verdict strings follow this detector family's uppercase house style
 * (MALICIOUS / SUSPICIOUS); scores below 55 stamp the score only.
 */
#include "share_change_detector_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "share_change_detector.h"

namespace {

#define SC_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "share change detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ShareEvent(const char* action, const char* name,
                      const char* path, const char* type) {
    edr::Event event;
    event.type = EDR_EVT_SHARE_CHANGE;
    event.ts100ns = 10000000ULL;
    event.fields[edr::field::kType] = "SHARE_CHANGE";
    event.fields[edr::field::kShareAction] = action;
    event.fields[edr::field::kShareName] = name;
    if (path != nullptr) event.fields[edr::field::kSharePath] = path;
    if (type != nullptr) event.fields[edr::field::kShareType] = type;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kShareChangeScore);
    return it == event.fields.end() ? "" : it->second;
}

std::string Verdict(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kShareChangeVerdict);
    return it == event.fields.end() ? "" : it->second;
}

std::string Signals(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kShareChangeSignals);
    return it == event.fields.end() ? "" : it->second;
}

bool Contains(const std::string& text, const char* needle) {
    return text.find(needle) != std::string::npos;
}

} // namespace

void RunShareChangeDetectorTests() {
    std::fprintf(stderr, "[share-change] TestInspects\n");
    {
        SC_CHECK(edr::ShareChangeDetector::Inspects(EDR_EVT_SHARE_CHANGE));
        SC_CHECK(!edr::ShareChangeDetector::Inspects(EDR_EVT_PROCESS_START));

        edr::ShareChangeDetector detector;
        edr::Event other;
        other.type = EDR_EVT_PROCESS_START;
        other.fields[edr::field::kType] = "PROCESS_START";
        detector.Enrich(other);
        SC_CHECK(Score(other).empty());
    }
    std::fprintf(stderr, "[share-change] TestHiddenRootShareMalicious\n");
    {
        /* added 20 + hidden ($) 25 + drive-root path 30 = 75 MALICIOUS. */
        edr::ShareChangeDetector detector;
        edr::Event event = ShareEvent("added", "C$", "C:\\", "disk");
        detector.Enrich(event);
        SC_CHECK(Score(event) == "75");
        SC_CHECK(Verdict(event) == "MALICIOUS");
        SC_CHECK(Contains(Signals(event), "share_added"));
        SC_CHECK(Contains(Signals(event), "_hidden"));
        SC_CHECK(Contains(Signals(event), "_sensitive_path"));
        SC_CHECK(Contains(Signals(event), "_disk"));
    }
    std::fprintf(stderr, "[share-change] TestSensitiveDirectoryShare\n");
    {
        /* added 20 + sensitive directory 30 = 50 -> score only. */
        edr::ShareChangeDetector detector;
        edr::Event event = ShareEvent(
            "added", "pub", "C:\\Users\\bob\\Desktop", "disk");
        detector.Enrich(event);
        SC_CHECK(Score(event) == "50");
        SC_CHECK(Verdict(event).empty());
        SC_CHECK(Signals(event).empty());
    }
    std::fprintf(stderr, "[share-change] TestOrdinaryShareLowSignal\n");
    {
        /* A plain project share on a non-sensitive path scores 20 only. */
        edr::ShareChangeDetector detector;
        edr::Event event = ShareEvent(
            "added", "projects", "D:\\projects\\data", "disk");
        detector.Enrich(event);
        SC_CHECK(Score(event) == "20");
        SC_CHECK(Verdict(event).empty());
    }
    std::fprintf(stderr, "[share-change] TestPrintAndIpcIgnored\n");
    {
        /* Print/IPC shares churn constantly and are never scored. */
        edr::ShareChangeDetector detector;
        edr::Event printAdded = ShareEvent("added", "HP$", "C:\\", "print");
        detector.Enrich(printAdded);
        SC_CHECK(Score(printAdded).empty());

        edr::Event ipcModified = ShareEvent("modified", "IPC$", "C:\\", "ipc");
        detector.Enrich(ipcModified);
        SC_CHECK(Score(ipcModified).empty());
    }
    std::fprintf(stderr, "[share-change] TestModifiedSensitivePath\n");
    {
        /* modified 10 + sensitive path 30 = 40 -> score only. */
        edr::ShareChangeDetector detector;
        edr::Event event = ShareEvent(
            "modified", "wwwroot", "C:\\inetpub\\wwwroot", "disk");
        detector.Enrich(event);
        SC_CHECK(Score(event) == "40");
        SC_CHECK(Verdict(event).empty());
    }
    std::fprintf(stderr, "[share-change] TestRemoval\n");
    {
        /* Removing a visible share (15) vs a hidden one (10). */
        edr::ShareChangeDetector detector;
        edr::Event visible = ShareEvent(
            "removed", "projects", "D:\\projects", "disk");
        detector.Enrich(visible);
        SC_CHECK(Score(visible) == "15");

        edr::Event hidden = ShareEvent("removed", "C$", "C:\\", "disk");
        detector.Enrich(hidden);
        SC_CHECK(Score(hidden) == "10");
    }
    std::fprintf(stderr, "[share-change] all passed\n");
}
