/* Unit tests for NamedPipeAbuseDetector. */
#include "named_pipe_abuse_detector_tests.h"

#include <cstdlib>
#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "named_pipe_abuse_detector.h"

namespace {

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error("named pipe abuse test failed at line " +
                                 std::to_string(line) + ": " + expression);
}
#define NP_CHECK(c) Check((c), #c, __LINE__)

edr::Event Pipe(uint64_t time, const char* name, const char* op,
                const char* pid) {
    edr::Event event;
    event.type = EDR_EVT_NAMED_PIPE;
    event.ts100ns = time;
    event.pid = static_cast<uint32_t>(std::strtoul(pid, nullptr, 10));
    event.fields[edr::field::kType] = "NAMED_PIPE";
    event.fields[edr::field::kPipeName] = name;
    event.fields[edr::field::kPipeOperation] = op;
    event.fields[edr::field::kPid] = pid;
    return event;
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunNamedPipeAbuseDetectorTests() {
    std::fprintf(stderr, "[named-pipe-abuse] TestDisabled\n");
    {
        edr::NamedPipeAbuseDetector detector(false, 55, 120, 32, 2, 60);
        auto event = Pipe(kSecond, "meterpreter", "created", "100");
        detector.Enrich(event);
        NP_CHECK(event.fields.find(edr::field::kNamedPipeAbuseScore) ==
                 event.fields.end());
    }

    std::fprintf(stderr, "[named-pipe-abuse] TestKnownToolName\n");
    {
        edr::NamedPipeAbuseDetector detector(true, 55, 120, 32, 2, 60);
        auto event = Pipe(kSecond, "meterpreter", "created", "100");
        detector.Enrich(event);
        NP_CHECK(event.fields.at(edr::field::kNamedPipeAbuseScore) == "75");
        NP_CHECK(event.fields.at(edr::field::kNamedPipeAbuseVerdict) ==
                 "malicious");
    }

    std::fprintf(stderr, "[named-pipe-abuse] TestCrossProcessActivity\n");
    {
        edr::NamedPipeAbuseDetector detector(true, 55, 120, 32, 2, 60);
        auto first = Pipe(kSecond, "{11111111-2222-3333-4444-555555555555}",
                          "created", "100");
        detector.Enrich(first);
        NP_CHECK(first.fields.find(edr::field::kNamedPipeAbuseScore) ==
                 first.fields.end());
        auto second = Pipe(2 * kSecond,
                           "{11111111-2222-3333-4444-555555555555}",
                           "connected", "200");
        detector.Enrich(second);
        NP_CHECK(second.fields.at(edr::field::kNamedPipeAbuseSignals).find(
                     "cross_process_pipe_activity") != std::string::npos);
        NP_CHECK(second.fields.at(edr::field::kNamedPipeAbuseDistinctPids) ==
                 "2");
    }

    std::fprintf(stderr, "[named-pipe-abuse] TestDedupAndExpiry\n");
    {
        edr::NamedPipeAbuseDetector detector(true, 55, 10, 32, 2, 60);
        auto first = Pipe(kSecond, "cobalt-beacon", "created", "100");
        detector.Enrich(first);
        auto second = Pipe(2 * kSecond, "cobalt-beacon", "created", "100");
        detector.Enrich(second);
        NP_CHECK(second.fields.find(edr::field::kNamedPipeAbuseScore) ==
                 second.fields.end());
        auto third = Pipe(70 * kSecond, "cobalt-beacon", "created", "100");
        detector.Enrich(third);
        NP_CHECK(third.fields.find(edr::field::kNamedPipeAbuseScore) !=
                 third.fields.end());
    }

    std::fprintf(stderr, "[named-pipe-abuse] TestBoundedState\n");
    {
        edr::NamedPipeAbuseDetector detector(true, 55, 120, 2, 2, 60);
        for (int i = 0; i < 5; ++i) {
            std::string name = "pipe-" + std::to_string(i) + "-meterpreter";
            auto event = Pipe((i + 1) * kSecond, name.c_str(), "created", "100");
            detector.Enrich(event);
        }
        NP_CHECK(detector.StateCount() <= 2);
    }
    std::fprintf(stderr, "[named-pipe-abuse] all passed\n");
}
