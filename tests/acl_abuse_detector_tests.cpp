/*
 * acl_abuse_detector_tests.cpp - Smoke tests for AclAbuseDetector.
 *
 * NOTE: reconstructed stub suite. The original test file written by a
 * concurrent session was lost to the documented shared-file rollback
 * failure mode (see CLAUDE.md); this minimal suite keeps the build
 * green until the full suite lands.
 */
#include "acl_abuse_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "acl_abuse_detector.h"

namespace {

#define AA_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "acl abuse detector test failed at line " +
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

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kAclAbuseScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunAclAbuseDetectorTests() {
    std::fprintf(stderr, "[acl-abuse] TestDisabled\n");
    {
        /* Disabled detector never stamps. */
        edr::AclAbuseDetector detector(false, 55, 300, 1024);
        edr::Event event = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\icacls.exe",
            "icacls C:\\Users\\Public\\drop /grant Everyone:(F)");
        detector.Enrich(event);
        AA_CHECK(Score(event).empty());
    }
    std::fprintf(stderr, "[acl-abuse] TestIcaclsGrantEveryone\n");
    {
        edr::AclAbuseDetector detector(true, 55, 300, 1024);
        edr::Event grant = ProcEvent(
            1000 * kSecond, "C:\\Windows\\System32\\icacls.exe",
            "icacls C:\\Users\\Public\\drop /grant Everyone:(F)");
        detector.Enrich(grant);
        const std::string score = Score(grant);
        uint32_t value = 0;
        if (!score.empty()) value =
            static_cast<uint32_t>(std::stoul(score));
        AA_CHECK(value >= 55);
    }
    std::fprintf(stderr, "[acl-abuse] TestTakeOwn\n");
    {
        edr::AclAbuseDetector detector(true, 55, 300, 1024);
        edr::Event takeown = ProcEvent(
            1001 * kSecond, "C:\\Windows\\System32\\takeown.exe",
            "takeown /f C:\\Windows\\System32\\taskmgr.exe");
        detector.Enrich(takeown);
        const std::string score = Score(takeown);
        uint32_t value = 0;
        if (!score.empty()) value =
            static_cast<uint32_t>(std::stoul(score));
        AA_CHECK(value >= 55);
    }
    std::fprintf(stderr, "[acl-abuse] TestReadOnlyInspectionSilent\n");
    {
        /* Read-only ACL inspection is not scored. */
        edr::AclAbuseDetector detector(true, 55, 300, 1024);
        edr::Event inspect = ProcEvent(
            1002 * kSecond, "C:\\Windows\\System32\\icacls.exe",
            "icacls C:\\Users\\Public\\report.docx");
        detector.Enrich(inspect);
        AA_CHECK(Score(inspect).empty());
    }
    std::fprintf(stderr, "[acl-abuse] all passed\n");
}
