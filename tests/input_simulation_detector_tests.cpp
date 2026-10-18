/*
 * input_simulation_detector_tests.cpp - Unit tests for
 * InputSimulationDetector.
 */
#include "input_simulation_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "input_simulation_detector.h"

namespace {

#define IS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "input simulation detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event InputEvent(uint64_t ts100ns, uint32_t pid, const char* image) {
    edr::Event event;
    event.type = EDR_EVT_INPUT_SIMULATION;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.fields[edr::field::kType] = "INPUT_SIMULATION";
    event.fields[edr::field::kImage] = image;
    return event;
}

std::string Score(const edr::Event& event) {
    auto it = event.fields.find(edr::field::kInputSimScore);
    return it == event.fields.end() ? "" : it->second;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunInputSimulationDetectorTests() {
    std::fprintf(stderr, "[input-sim] TestDisabled\n");
    {
        edr::InputSimulationDetector detector(false, 60, 1024, 3);
        edr::Event event = InputEvent(1000 * kSecond, 1001,
                                      "C:\\Tools\\macro.exe");
        detector.Enrich(event);
        IS_CHECK(Score(event).empty());
    }

    std::fprintf(stderr, "[input-sim] TestBurstAndSystemProcess\n");
    {
        edr::InputSimulationDetector detector(true, 60, 1024, 3);
        edr::Event first = InputEvent(1000 * kSecond, 1001,
                                      "C:\\Tools\\macro.exe");
        detector.Enrich(first);
        IS_CHECK(Score(first) == "40");

        edr::Event second = InputEvent(1001 * kSecond, 1001,
                                       "C:\\Tools\\macro.exe");
        detector.Enrich(second);
        IS_CHECK(Score(second) == "40");

        edr::Event third = InputEvent(1002 * kSecond, 1001,
                                      "C:\\Tools\\macro.exe");
        detector.Enrich(third);
        IS_CHECK(Score(third) == "70");
        IS_CHECK(third.fields.at(edr::field::kInputSimVerdict) == "SUSPICIOUS");

        edr::Event system = InputEvent(1003 * kSecond, 1002,
                                       "C:\\Windows\\System32\\explorer.exe");
        detector.Enrich(system);
        IS_CHECK(Score(system).empty() || Score(system) == "0");
    }

    std::fprintf(stderr, "[input-sim] all passed\n");
}
