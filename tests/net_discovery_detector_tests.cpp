/*
 * net_discovery_detector_tests.cpp - Unit tests for NetDiscoveryDetector.
 */
#include "net_discovery_detector_tests.h"

#include <windows.h>

#include <cstdio>
#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "net_discovery_detector.h"

namespace {

#define NDISC_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "net discovery detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event ProcessStart(uint64_t ts100ns, const char* commandLine) {
    edr::Event event;
    event.type = EDR_EVT_PROCESS_START;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "PROCESS_START";
    if (commandLine != nullptr)
        event.fields[edr::field::kCommandLine] = commandLine;
    return event;
}

edr::Event ScriptBlock(uint64_t ts100ns, const char* body) {
    edr::Event event;
    event.type = EDR_EVT_POWERSHELL_SCRIPT;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "POWERSHELL_SCRIPT";
    /* House contract: script bodies live only in kScriptBlockText. */
    event.fields[edr::field::kScriptBlockText] = body;
    return event;
}

bool HasScore(const edr::Event& event) {
    return event.fields.find(edr::field::kNetDiscoveryScore) !=
           event.fields.end();
}

uint32_t Score(const edr::Event& event) {
    return static_cast<uint32_t>(
        std::stoul(event.fields.at(edr::field::kNetDiscoveryScore)));
}

constexpr uint64_t kSecond = 10000000ULL;

} // namespace

void RunNetDiscoveryDetectorTests() {
    std::fprintf(stderr, "[net_discovery] TestDisabled\n");
    {
        edr::NetDiscoveryDetector detector(false, 55, 300, 4, 300, 1024);
        auto event = ProcessStart(kSecond, "net view \\\\filesrv");
        detector.Enrich(event);
        NDISC_CHECK(!HasScore(event));
    }

    std::fprintf(stderr, "[net_discovery] SingleNetView\n");
    {
        edr::NetDiscoveryDetector detector(true, 55, 300, 4, 300, 1024);
        auto event = ProcessStart(10 * kSecond, "net view \\\\filesrv01");
        detector.Enrich(event);
        NDISC_CHECK(HasScore(event));
        NDISC_CHECK(Score(event) == 55);
        NDISC_CHECK(event.fields.at(edr::field::kNetDiscoveryVerdict) ==
                    "suspicious");
    }

    std::fprintf(stderr, "[net_discovery] NetstatPidCorrelation\n");
    {
        edr::NetDiscoveryDetector detector(true, 55, 300, 4, 300, 1024);
        auto event = ProcessStart(10 * kSecond, "netstat -ano");
        detector.Enrich(event);
        NDISC_CHECK(HasScore(event));
        NDISC_CHECK(Score(event) == 70);
        NDISC_CHECK(event.fields.at(edr::field::kNetDiscoveryVerdict) ==
                    "suspicious");
    }

    std::fprintf(stderr, "[net_discovery] AdReconNltest\n");
    {
        edr::NetDiscoveryDetector detector(true, 55, 300, 4, 300, 1024);
        auto event =
            ProcessStart(10 * kSecond, "nltest /dclist:corp.local");
        detector.Enrich(event);
        NDISC_CHECK(HasScore(event));
        NDISC_CHECK(Score(event) == 60);
    }

    std::fprintf(stderr, "[net_discovery] PingSweepBurst\n");
    {
        edr::NetDiscoveryDetector detector(true, 55, 300, 4, 300, 1024);
        /* Single pings stay silent... */
        for (int i = 1; i <= 3; ++i) {
            const std::string cmd =
                "ping -n 1 10.0.0." + std::to_string(i);
            auto event = ProcessStart((10 + i) * kSecond, cmd.c_str());
            detector.Enrich(event);
            NDISC_CHECK(!HasScore(event));
        }
        /* ...4th distinct target inside the window trips the burst. */
        auto fourth = ProcessStart(14 * kSecond, "ping -n 1 10.0.0.4");
        detector.Enrich(fourth);
        NDISC_CHECK(HasScore(fourth));
        NDISC_CHECK(Score(fourth) == 80);
        NDISC_CHECK(fourth.fields.at(edr::field::kNetDiscoveryVerdict) ==
                    "malicious");
    }

    std::fprintf(stderr, "[net_discovery] BurstWindowExpiry\n");
    {
        edr::NetDiscoveryDetector detector(true, 55, 60, 4, 300, 1024);
        /* Four pings but spaced 120s apart in a 60s window -> no burst. */
        for (int i = 1; i <= 4; ++i) {
            const std::string cmd =
                "ping -n 1 10.0.1." + std::to_string(i);
            auto event = ProcessStart(
                static_cast<uint64_t>(i) * 120 * kSecond, cmd.c_str());
            detector.Enrich(event);
            NDISC_CHECK(!HasScore(event));
        }
    }

    std::fprintf(stderr, "[net_discovery] DedupSuppressesRepeat\n");
    {
        edr::NetDiscoveryDetector detector(true, 55, 300, 4, 300, 1024);
        auto first = ProcessStart(10 * kSecond, "net view \\\\filesrv02");
        detector.Enrich(first);
        NDISC_CHECK(HasScore(first));

        auto second = ProcessStart(20 * kSecond, "net view \\\\filesrv02");
        detector.Enrich(second);
        NDISC_CHECK(!HasScore(second));

        /* Different target -> not suppressed. */
        auto third = ProcessStart(30 * kSecond, "net view \\\\filesrv03");
        detector.Enrich(third);
        NDISC_CHECK(HasScore(third));
    }

    std::fprintf(stderr, "[net_discovery] MinScoreFiltersLowSignals\n");
    {
        edr::NetDiscoveryDetector detector(true, 70, 300, 4, 300, 1024);
        /* arp -a scores 55, filtered by min_score=70. */
        auto event = ProcessStart(10 * kSecond, "arp -a");
        detector.Enrich(event);
        NDISC_CHECK(!HasScore(event));
    }

    std::fprintf(stderr, "[net_discovery] SinglePingSilent\n");
    {
        edr::NetDiscoveryDetector detector(true, 55, 300, 4, 300, 1024);
        auto event = ProcessStart(10 * kSecond, "ping -n 1 8.8.8.8");
        detector.Enrich(event);
        NDISC_CHECK(!HasScore(event));
    }

    std::fprintf(stderr, "[net_discovery] ScriptBlockFace\n");
    {
        edr::NetDiscoveryDetector detector(true, 55, 300, 4, 300, 1024);
        auto event = ScriptBlock(10 * kSecond, "Get-NetTCPConnection");
        detector.Enrich(event);
        NDISC_CHECK(HasScore(event));
        NDISC_CHECK(Score(event) == 55);
    }

    std::fprintf(stderr, "[net_discovery] all passed\n");
}
