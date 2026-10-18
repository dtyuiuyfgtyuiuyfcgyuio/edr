/*
 * ppid_spoof_detector_tests.cpp - Unit tests for PpidSpoofDetector.
 */
#include "ppid_spoof_detector_tests.h"

#include <windows.h>

#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "ppid_spoof_detector.h"

namespace {

#define PPID_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "ppid spoof detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcessStart(uint64_t ts100ns, const char* image,
                        const char* parentImage, uint32_t ppid) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.ppid = ppid;
    event.fields[edr::field::kType] = "PROCESS_START";
    if (image != nullptr)
        event.fields[edr::field::kImage] = image;
    if (parentImage != nullptr && parentImage[0] != '\0')
        event.fields[edr::field::kParentImage] = parentImage;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kPpidSpoofScore) !=
           event.fields.end();
}

uint32_t Score(const edr::Event& event) {
    return static_cast<uint32_t>(
        std::stoul(event.fields.at(edr::field::kPpidSpoofScore)));
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunPpidSpoofDetectorTests() {
    std::fprintf(stderr, "[ppid_spoof] TestDisabled\n");
    {
        edr::PpidSpoofDetector detector(false, 55, 300, 1024);
        auto event = ProcessStart(kSecond,
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\System32\\cmd.exe", 1234);
        detector.Enrich(event);
        PPID_CHECK(!HasScore(event));
    }

    std::fprintf(stderr, "[ppid_spoof] SystemBinaryWrongParent\n");
    {
        edr::PpidSpoofDetector detector(true, 55, 300, 1024);
        /* svchost.exe spawned by cmd.exe instead of services.exe -> 90. */
        auto event = ProcessStart(10 * kSecond,
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Users\\attacker\\cmd.exe", 5678);
        detector.Enrich(event);
        PPID_CHECK(HasScore(event));
        PPID_CHECK(Score(event) == 90);
        PPID_CHECK(event.fields.at(edr::field::kPpidSpoofVerdict) ==
                   "malicious");
    }

    std::fprintf(stderr, "[ppid_spoof] LsassWrongParent\n");
    {
        edr::PpidSpoofDetector detector(true, 55, 300, 1024);
        /* lsass.exe spawned by powershell.exe -> 90. */
        auto event = ProcessStart(10 * kSecond,
            "C:\\Windows\\System32\\lsass.exe",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            9999);
        detector.Enrich(event);
        PPID_CHECK(HasScore(event));
        PPID_CHECK(Score(event) == 90);
    }

    std::fprintf(stderr, "[ppid_spoof] LegitimateSvchost\n");
    {
        edr::PpidSpoofDetector detector(true, 55, 300, 1024);
        /* svchost.exe spawned by services.exe -> no alert. */
        auto event = ProcessStart(10 * kSecond,
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\System32\\services.exe", 500);
        detector.Enrich(event);
        PPID_CHECK(!HasScore(event));
    }

    std::fprintf(stderr, "[ppid_spoof] LegitimateLsass\n");
    {
        edr::PpidSpoofDetector detector(true, 55, 300, 1024);
        auto event = ProcessStart(10 * kSecond,
            "C:\\Windows\\System32\\lsass.exe",
            "C:\\Windows\\System32\\winlogon.exe", 400);
        detector.Enrich(event);
        PPID_CHECK(!HasScore(event));
    }

    std::fprintf(stderr, "[ppid_spoof] KernelPidEmptyParentSilent\n");
    {
        edr::PpidSpoofDetector detector(true, 55, 300, 1024);
        /* ppid=0 with empty parent image -> signal 3 guard
         * (!rawParent.empty()) suppresses; no alert. */
        auto event = ProcessStart(10 * kSecond,
            "C:\\temp\\malware.exe",
            "", /* empty parent image */
            0);
        detector.Enrich(event);
        PPID_CHECK(!HasScore(event));
    }

    std::fprintf(stderr, "[ppid_spoof] KernelPidParentPositive\n");
    {
        edr::PpidSpoofDetector detector(true, 55, 300, 1024);
        /* User-mode binary claiming PID 4 (System) as parent -> 60. */
        auto event = ProcessStart(10 * kSecond,
            "C:\\temp\\malware.exe",
            "System", 4);
        detector.Enrich(event);
        PPID_CHECK(HasScore(event));
        PPID_CHECK(Score(event) == 60);
        PPID_CHECK(event.fields.at(edr::field::kPpidSpoofVerdict) ==
                   "suspicious");
    }

    std::fprintf(stderr, "[ppid_spoof] KernelPidKnownBinaryExempt\n");
    {
        edr::PpidSpoofDetector detector(true, 55, 300, 1024);
        /* smss.exe legitimately starts under PID 4 (System) -> exempt. */
        auto event = ProcessStart(10 * kSecond,
            "C:\\Windows\\System32\\smss.exe",
            "System", 4);
        detector.Enrich(event);
        PPID_CHECK(!HasScore(event));
    }

    std::fprintf(stderr, "[ppid_spoof] DedupSuppressesRepeat\n");
    {
        edr::PpidSpoofDetector detector(true, 55, 60, 1024);
        auto first = ProcessStart(10 * kSecond,
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Users\\attacker\\cmd.exe", 1111);
        detector.Enrich(first);
        PPID_CHECK(HasScore(first));

        /* Same pair within dedup window -> suppressed. */
        auto second = ProcessStart(20 * kSecond,
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Users\\attacker\\cmd.exe", 2222);
        detector.Enrich(second);
        PPID_CHECK(!HasScore(second));

        /* Different child basename -> not suppressed. */
        auto third = ProcessStart(30 * kSecond,
            "C:\\Windows\\System32\\lsass.exe",
            "C:\\Users\\attacker\\cmd.exe", 3333);
        detector.Enrich(third);
        PPID_CHECK(HasScore(third));
    }

    std::fprintf(stderr, "[ppid_spoof] MinScoreFiltersLowSignals\n");
    {
        edr::PpidSpoofDetector detector(true, 70, 300, 1024);
        /* Score 60 signal filtered by min_score=70. */
        auto event = ProcessStart(10 * kSecond,
            "C:\\temp\\tool.exe",
            "C:\\Windows\\System32\\ntoskrnl.exe", 4);
        detector.Enrich(event);
        if (HasScore(event))
            PPID_CHECK(Score(event) >= 70);
    }

    std::fprintf(stderr, "[ppid_spoof] all passed\n");
}
