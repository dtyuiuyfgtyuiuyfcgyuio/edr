/* Unit tests for HandleGuardDetector. */
#include "handle_guard_detector_tests.h"

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "handle_guard_detector.h"

namespace {

#define HG_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "handle guard detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event Handle(uint64_t ts100ns, const char* objectType,
                  const char* accessMask, const char* caller = "100",
                  const char* target = "200") {
    edr::Event event;
    event.type = EDR_EVT_HANDLE_OPEN;
    event.ts100ns = ts100ns;
    event.pid = 100;
    event.fields[edr::field::kType] = "HANDLE_OPEN";
    event.fields[edr::field::kObjectType] = objectType;
    event.fields[edr::field::kAccessMask] = accessMask;
    event.fields[edr::field::kPid] = caller;
    event.fields[edr::field::kTargetPid] = target;
    return event;
}

std::string Score(const edr::Event& event) {
    const auto it = event.fields.find(edr::field::kHandleGuardScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunHandleGuardDetectorTests() {
    std::fprintf(stderr, "[handle-guard] TestDisabled\n");
    {
        edr::HandleGuardDetector detector(false, 55, 300, 1024);
        edr::Event event = Handle(1000 * kSecond, "process", "56");
        detector.Enrich(event);
        HG_CHECK(Score(event).empty());
    }

    std::fprintf(stderr, "[handle-guard] TestProcessMemoryChain\n");
    {
        edr::HandleGuardDetector detector(true, 55, 300, 1024);
        edr::Event event = Handle(1000 * kSecond, "process", "56");
        detector.Enrich(event); /* VM_OPERATION + VM_READ + VM_WRITE */
        HG_CHECK(Score(event) == "90");
        HG_CHECK(event.fields.at(edr::field::kHandleGuardVerdict) ==
                 "malicious");
    }

    std::fprintf(stderr, "[handle-guard] TestThreadHijack\n");
    {
        edr::HandleGuardDetector detector(true, 55, 300, 1024);
        edr::Event event = Handle(1000 * kSecond, "thread", "58");
        detector.Enrich(event); /* suspend + get/set context */
        HG_CHECK(Score(event) == "100");
    }

    std::fprintf(stderr, "[handle-guard] TestLowRiskSilent\n");
    {
        edr::HandleGuardDetector detector(true, 55, 300, 1024);
        edr::Event event = Handle(1000 * kSecond, "process", "16");
        detector.Enrich(event);
        HG_CHECK(Score(event).empty());
    }

    std::fprintf(stderr, "[handle-guard] TestDedupWindow\n");
    {
        edr::HandleGuardDetector detector(true, 55, 60, 1024);
        edr::Event first = Handle(1000 * kSecond, "process", "56");
        detector.Enrich(first);
        HG_CHECK(!Score(first).empty());
        edr::Event second = Handle(1030 * kSecond, "process", "56");
        detector.Enrich(second);
        HG_CHECK(Score(second).empty());
        edr::Event third = Handle(1100 * kSecond, "process", "56");
        detector.Enrich(third);
        HG_CHECK(!Score(third).empty());
    }

    std::fprintf(stderr, "[handle-guard] TestBoundedState\n");
    {
        edr::HandleGuardDetector detector(true, 55, 300, 2);
        for (int i = 0; i < 5; ++i) {
            edr::Event event = Handle((1000 + i) * kSecond, "process", "56",
                                      std::to_string(100 + i).c_str(), "200");
            detector.Enrich(event);
        }
        HG_CHECK(detector.StateCount() <= 2);
    }

    std::fprintf(stderr, "[handle-guard] all passed\n");
}
