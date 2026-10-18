/*
 * port_scan_detector_tests.cpp - Unit tests for PortScanDetector.
 */
#include "port_scan_detector_tests.h"

#include <stdexcept>
#include <string>

#include "edr_event.h"
#include "event_bus.h"
#include "port_scan_detector.h"

namespace {

#define PS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "port scan detector test failed at line " + std::to_string(line) +
            ": " + expression);
}

edr::Event NetConnect(uint32_t pid, const char* image, const char* ip,
                      const char* port, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_NET_CONNECT;
    event.ts100ns = ts100ns;
    event.pid = pid;
    event.fields[edr::field::kType] = "NET_CONNECT";
    if (image) event.fields[edr::field::kImage] = image;
    if (ip) event.fields[edr::field::kDstIp] = ip;
    if (port) event.fields[edr::field::kDstPort] = port;
    return event;
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

void TestPidZeroIgnored() {
    edr::PortScanDetector detector(true, 30, 4096, 5);
    edr::Event event =
        NetConnect(0, "C:\\evil\\nmap.exe", "10.0.0.1", "22", 1000);
    detector.Enrich(event);
    PS_CHECK(!HasField(event, edr::field::kPortScanScore));
    PS_CHECK(detector.StateCount() == 0);
}

void TestScanFlaggedOnSameHost() {
    edr::PortScanDetector detector(true, 30, 4096, 5);
    const uint64_t base = 100000000000ULL;
    const char* image = "C:\\Windows\\Temp\\scanner.exe";

    for (int port = 1; port <= 4; ++port) {
        edr::Event event = NetConnect(
            4242, image, "10.0.0.8", std::to_string(port).c_str(),
            base + static_cast<uint64_t>(port) * 10000000ULL);
        detector.Enrich(event);
        PS_CHECK(!HasField(event, edr::field::kPortScanScore));
    }

    edr::Event fifth = NetConnect(4242, image, "10.0.0.8", "5",
                                  base + 50000000ULL);
    detector.Enrich(fifth);
    PS_CHECK(HasField(fifth, edr::field::kPortScanScore));
    PS_CHECK(fifth.fields.at(edr::field::kPortScanScore) == "20");
    PS_CHECK(fifth.fields.at(edr::field::kPortScanPortCount) == "5");
    PS_CHECK(fifth.fields.at(edr::field::kPortScanTarget) == "10.0.0.8");
    PS_CHECK(fifth.fields.at(edr::field::kPortScanSamplePorts) ==
             "1,2,3,4,5");
    PS_CHECK(fifth.fields.at(edr::field::kPortScanWindowSeconds) == "30");
    PS_CHECK(detector.StateCount() == 1);

    /* Already flagged: later ports on the same key do not re-stamp. */
    edr::Event sixth = NetConnect(4242, image, "10.0.0.8", "6",
                                  base + 60000000ULL);
    detector.Enrich(sixth);
    PS_CHECK(!HasField(sixth, edr::field::kPortScanScore));
}

void TestSplitAcrossHostsDoesNotFlag() {
    edr::PortScanDetector detector(true, 30, 4096, 5);
    const uint64_t base = 200000000000ULL;
    const char* image = "C:\\evil\\scanner.exe";
    for (int i = 1; i <= 8; ++i) {
        std::string ip = "10.0.0." + std::to_string(i);
        edr::Event event = NetConnect(
            7, image, ip.c_str(), std::to_string(20 + i).c_str(),
            base + static_cast<uint64_t>(i) * 10000000ULL);
        detector.Enrich(event);
        PS_CHECK(!HasField(event, edr::field::kPortScanScore));
    }
    PS_CHECK(detector.StateCount() == 1);
}

void TestWindowExpiryResetsFlag() {
    edr::PortScanDetector detector(true, 30, 4096, 3);
    const uint64_t base = 300000000000ULL;
    const char* image = "C:\\evil\\scanner.exe";
    const uint64_t window = 30ULL * 10000000ULL;

    for (int port = 1; port <= 3; ++port) {
        edr::Event event = NetConnect(
            9, image, "10.1.1.1", std::to_string(port).c_str(),
            base + static_cast<uint64_t>(port) * 10000000ULL);
        detector.Enrich(event);
        if (port < 3)
            PS_CHECK(!HasField(event, edr::field::kPortScanScore));
        else
            PS_CHECK(HasField(event, edr::field::kPortScanScore));
    }

    edr::Event expired = NetConnect(9, image, "10.1.1.1", "22",
                                    base + window + 40000000ULL);
    detector.Enrich(expired);
    PS_CHECK(!HasField(expired, edr::field::kPortScanScore));
    PS_CHECK(detector.StateCount() == 1);

    edr::Event second = NetConnect(9, image, "10.1.1.1", "23",
                                   base + window + 50000000ULL);
    detector.Enrich(second);
    PS_CHECK(!HasField(second, edr::field::kPortScanScore));

    edr::Event third = NetConnect(9, image, "10.1.1.1", "24",
                                  base + window + 60000000ULL);
    detector.Enrich(third);
    PS_CHECK(HasField(third, edr::field::kPortScanScore));
    PS_CHECK(third.fields.at(edr::field::kPortScanPortCount) == "3");
}

void TestDisabledAndFilters() {
    edr::PortScanDetector disabled(false, 30, 4096, 2);
    edr::Event event =
        NetConnect(11, "scan.exe", "10.0.0.1", "22", 1000);
    disabled.Enrich(event);
    PS_CHECK(!HasField(event, edr::field::kPortScanScore));
    PS_CHECK(disabled.StateCount() == 0);

    edr::PortScanDetector detector(true, 30, 4096, 2);
    PS_CHECK(edr::PortScanDetector::Inspects(EDR_EVT_NET_CONNECT));
    PS_CHECK(!edr::PortScanDetector::Inspects(EDR_EVT_PROCESS_START));

    auto feed = [&](const char* ip, const char* port, uint64_t ts100ns) {
        edr::Event connect = NetConnect(11, "scan.exe", ip, port, ts100ns);
        detector.Enrich(connect);
    };
    feed("127.0.0.1", "22", 2000);
    feed("::1", "22", 3000);
    feed("10.0.0.1", "0", 4000);
    feed("10.0.0.1", "65536", 5000);
    feed("", "22", 6000);
    PS_CHECK(detector.StateCount() == 0);

    feed("10.0.0.1", "22", 7000);
    PS_CHECK(detector.StateCount() == 1);
}

void TestCapacityEviction() {
    edr::PortScanDetector detector(true, 30, 2, 50);
    const uint64_t base = 400000000000ULL;
    auto feed = [&](uint32_t pid, const char* image, const char* ip,
                    uint64_t ts100ns) {
        edr::Event connect = NetConnect(pid, image, ip, "1", ts100ns);
        detector.Enrich(connect);
    };
    feed(1, "a.exe", "10.0.0.1", base);
    feed(2, "b.exe", "10.0.0.2", base + 1);
    PS_CHECK(detector.StateCount() == 2);
    feed(3, "c.exe", "10.0.0.3", base + 2);
    PS_CHECK(detector.StateCount() == 2);
}

} // namespace

void RunPortScanDetectorTests() {
    TestPidZeroIgnored();
    TestScanFlaggedOnSameHost();
    TestSplitAcrossHostsDoesNotFlag();
    TestWindowExpiryResetsFlag();
    TestDisabledAndFilters();
    TestCapacityEviction();
}
