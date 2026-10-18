/*
 * lateral_movement_detector_tests.cpp - Unit tests for LateralMovementDetector.
 */
#include "lateral_movement_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>

#include "lateral_movement_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define LM_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "lateral movement detector test failed at line " +
            std::to_string(line) + ": " + expression);
}

edr::Event NetConnect(uint32_t pid, const char* image,
                      const char* dstIp, const char* dstPort,
                      uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_NET_CONNECT;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.fields[edr::field::kType] = "NET_CONNECT";
    if (image)   event.fields[edr::field::kImage]   = image;
    if (dstIp)   event.fields[edr::field::kDstIp]   = dstIp;
    if (dstPort) event.fields[edr::field::kDstPort]  = dstPort;
    return event;
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

/* V1: pid-keyed attribution; fires when minDestCount distinct IPs
 * are reached on lateral-movement ports. */
void TestBasicSmbScanFlagged() {
    /* minDestCount = 3, scorePerDest = 20 */
    edr::LateralMovementDetector det(true, 120, 4096, 3, 20);
    const uint64_t base = 100000000000ULL;
    const char* image = "C:\\evil\\scanner.exe";
    edr::Event last;

    const char* hosts[] = {"10.0.0.1", "10.0.0.2", "10.0.0.3"};
    for (int i = 0; i < 3; ++i) {
        last = NetConnect(1001, image, hosts[i], "445",
                          base + static_cast<uint64_t>(i) * 1000000ULL);
        det.Enrich(last);
    }

    LM_CHECK(HasField(last, edr::field::kLateralMoveScore));
    LM_CHECK(last.fields.at(edr::field::kLateralMoveScore) == "60"); /* 3 * 20 */
    LM_CHECK(last.fields.at(edr::field::kLateralMoveDestCount) == "3");
    LM_CHECK(last.fields.at(edr::field::kLateralMovePorts) == "445");
    LM_CHECK(last.fields.at(edr::field::kLateralMoveWindowSeconds) == "120");
    LM_CHECK(det.StateCount() == 1);
}

/* V2: repeated connections to the SAME destination do not inflate destCount. */
void TestSameDestinationNoInflation() {
    edr::LateralMovementDetector det(true, 120, 4096, 3, 20);
    const uint64_t base = 200000000000ULL;
    edr::Event last;

    for (int i = 0; i < 10; ++i) {
        last = NetConnect(2001, "C:\\evil\\bot.exe", "192.168.1.1", "445",
                          base + static_cast<uint64_t>(i) * 1000000ULL);
        det.Enrich(last);
    }
    /* Only 1 distinct destination — should NOT fire. */
    LM_CHECK(!HasField(last, edr::field::kLateralMoveScore));
    LM_CHECK(!HasField(last, edr::field::kLateralMoveDestCount));
}

/* V3: connections to non-lateral ports are ignored. */
void TestNonLateralPortIgnored() {
    edr::LateralMovementDetector det(true, 120, 4096, 3, 20);
    const uint64_t base = 300000000000ULL;
    edr::Event last;

    const char* hosts[] = {"10.1.0.1", "10.1.0.2", "10.1.0.3"};
    for (int i = 0; i < 3; ++i) {
        last = NetConnect(3001, "C:\\evil\\scan.exe", hosts[i], "8080",
                          base + static_cast<uint64_t>(i) * 1000000ULL);
        det.Enrich(last);
    }
    LM_CHECK(!HasField(last, edr::field::kLateralMoveScore));
    LM_CHECK(det.StateCount() == 0);
}

/* V4: loopback destinations (127.x.x.x) are excluded. */
void TestLoopbackExcluded() {
    edr::LateralMovementDetector det(true, 120, 4096, 2, 20);
    const uint64_t base = 400000000000ULL;

    /* Two loopback IPs on SMB — should NOT contribute to destCount. */
    for (int i = 0; i < 3; ++i) {
        edr::Event ev = NetConnect(4001, "C:\\evil\\scan.exe",
                                   "127.0.0.1", "445",
                                   base + static_cast<uint64_t>(i) * 1000000ULL);
        det.Enrich(ev);
    }
    LM_CHECK(det.StateCount() == 0); /* skipped before key creation */
}

/* V5: RDP scan fires (port 3389). */
void TestRdpScanFlagged() {
    edr::LateralMovementDetector det(true, 120, 4096, 2, 25);
    const uint64_t base = 500000000000ULL;
    const char* image = "C:\\pentest\\rdpscan.exe";
    edr::Event last;

    edr::Event a = NetConnect(5001, image, "172.16.0.1", "3389", base);
    det.Enrich(a);
    last = NetConnect(5001, image, "172.16.0.2", "3389", base + 1000000ULL);
    det.Enrich(last);

    LM_CHECK(HasField(last, edr::field::kLateralMoveScore));
    LM_CHECK(last.fields.at(edr::field::kLateralMoveScore) == "50"); /* 2 * 25 */
    LM_CHECK(last.fields.at(edr::field::kLateralMoveDestCount) == "2");
    LM_CHECK(last.fields.at(edr::field::kLateralMovePorts) == "3389");
}

/* V6: mixed-port scan accumulates ports string. */
void TestMixedPortsScanFlagged() {
    edr::LateralMovementDetector det(true, 120, 4096, 3, 20);
    const uint64_t base = 600000000000ULL;
    const char* image = "C:\\pentest\\multiscan.exe";
    edr::Event last;

    last = NetConnect(6001, image, "10.0.1.1", "445",  base);
    det.Enrich(last);
    last = NetConnect(6001, image, "10.0.1.2", "3389", base + 1000000ULL);
    det.Enrich(last);
    last = NetConnect(6001, image, "10.0.1.3", "135",  base + 2000000ULL);
    det.Enrich(last);

    LM_CHECK(HasField(last, edr::field::kLateralMoveScore));
    LM_CHECK(last.fields.at(edr::field::kLateralMoveDestCount) == "3");
    /* ports are stored sorted numerically as strings in a std::set<std::string>.
     * std::set uses lexicographic order: 135, 3389, 445. */
    const std::string ports = last.fields.at(edr::field::kLateralMovePorts);
    LM_CHECK(ports.find("445") != std::string::npos);
    LM_CHECK(ports.find("3389") != std::string::npos);
    LM_CHECK(ports.find("135") != std::string::npos);
}

/* V7: window expiry resets the flag. */
void TestWindowExpiry() {
    edr::LateralMovementDetector det(true, 60, 4096, 2, 20);
    const uint64_t base = 700000000000ULL;
    const char* image = "C:\\evil\\scan.exe";

    edr::Event a = NetConnect(7001, image, "10.2.0.1", "445", base);
    det.Enrich(a);
    edr::Event b = NetConnect(7001, image, "10.2.0.2", "445", base + 1000000ULL);
    det.Enrich(b);
    LM_CHECK(HasField(b, edr::field::kLateralMoveScore));

    /* Advance past 60s window to expire the key. */
    edr::Event c = NetConnect(7001, image, "10.2.0.3", "445",
                              base + 700000000ULL); /* +70s */
    det.Enrich(c);
    LM_CHECK(!HasField(c, edr::field::kLateralMoveScore));

    /* Re-meet threshold in new window. */
    edr::Event d = NetConnect(7001, image, "10.2.0.4", "445",
                              base + 710000000ULL);
    det.Enrich(d);
    LM_CHECK(HasField(d, edr::field::kLateralMoveScore));
    LM_CHECK(d.fields.at(edr::field::kLateralMoveDestCount) == "2");
}

/* V8: disabled detector is a no-op. */
void TestDisabled() {
    edr::LateralMovementDetector det(false, 120, 4096, 2, 20);
    const uint64_t base = 800000000000ULL;
    edr::Event last;

    for (int i = 0; i < 5; ++i) {
        std::string ip = "10.3.0." + std::to_string(i + 1);
        last = NetConnect(8001, "C:\\evil\\scan.exe",
                          ip.c_str(), "445",
                          base + static_cast<uint64_t>(i) * 1000000ULL);
        det.Enrich(last);
    }
    LM_CHECK(!HasField(last, edr::field::kLateralMoveScore));
    LM_CHECK(det.StateCount() == 0);
}

/* V9: capacity eviction bounds state size. */
void TestCapacityEviction() {
    edr::LateralMovementDetector det(true, 120, 2, 3, 20);
    const uint64_t base = 900000000000ULL;

    for (uint32_t pid = 1; pid <= 3; ++pid) {
        edr::Event ev = NetConnect(pid, "C:\\scan.exe", "10.4.0.1", "445",
                                   base + static_cast<uint64_t>(pid) * 1000000ULL);
        det.Enrich(ev);
    }
    LM_CHECK(det.StateCount() <= 2);
}

/* V10: score is capped at 100. */
void TestScoreCap() {
    edr::LateralMovementDetector det(true, 120, 4096, 3, 50);
    const uint64_t base = 1000000000000ULL;
    const char* image = "C:\\scan.exe";
    edr::Event last;
    edr::Event stamped; /* the event that carried the derived fields */

    for (int i = 0; i < 5; ++i) {
        const std::string ip = "10.5.0." + std::to_string(i + 1);
        last = NetConnect(9001, image, ip.c_str(), "445",
                          base + static_cast<uint64_t>(i) * 1000000ULL);
        det.Enrich(last);
        if (HasField(last, edr::field::kLateralMoveScore)) stamped = last;
    }
    /* score = min(100, 5 * 50) = 100 */
    LM_CHECK(HasField(stamped, edr::field::kLateralMoveScore));
    LM_CHECK(stamped.fields.at(edr::field::kLateralMoveScore) == "100");
}

/* V11: Inspects() is true only for NET_CONNECT. */
void TestInspects() {
    LM_CHECK(edr::LateralMovementDetector::Inspects(EDR_EVT_NET_CONNECT));
    LM_CHECK(!edr::LateralMovementDetector::Inspects(EDR_EVT_DNS_QUERY));
    LM_CHECK(!edr::LateralMovementDetector::Inspects(EDR_EVT_PROCESS_START));
    LM_CHECK(!edr::LateralMovementDetector::Inspects(EDR_EVT_FILE_CREATE));
}

} // namespace

void RunLateralMovementDetectorTests() {
    std::printf("[lateral_move] TestBasicSmbScanFlagged\n");
    TestBasicSmbScanFlagged();
    std::printf("[lateral_move] TestSameDestinationNoInflation\n");
    TestSameDestinationNoInflation();
    std::printf("[lateral_move] TestNonLateralPortIgnored\n");
    TestNonLateralPortIgnored();
    std::printf("[lateral_move] TestLoopbackExcluded\n");
    TestLoopbackExcluded();
    std::printf("[lateral_move] TestRdpScanFlagged\n");
    TestRdpScanFlagged();
    std::printf("[lateral_move] TestMixedPortsScanFlagged\n");
    TestMixedPortsScanFlagged();
    std::printf("[lateral_move] TestWindowExpiry\n");
    TestWindowExpiry();
    std::printf("[lateral_move] TestDisabled\n");
    TestDisabled();
    std::printf("[lateral_move] TestCapacityEviction\n");
    TestCapacityEviction();
    std::printf("[lateral_move] TestScoreCap\n");
    TestScoreCap();
    std::printf("[lateral_move] TestInspects\n");
    TestInspects();
    std::printf("[lateral_move] all passed\n");
}
