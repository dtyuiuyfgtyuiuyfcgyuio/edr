/*
 * c2_beacon_detector_tests.cpp - Unit tests for C2BeaconDetector.
 */
#include "c2_beacon_detector_tests.h"

#include <windows.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "c2_beacon_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define C2_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition)
        throw std::runtime_error(
            "c2 beacon detector test failed at line " + std::to_string(line) +
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

size_t CountCommaSeparated(const std::string& value) {
    if (value.empty()) return 0;
    size_t count = 1;
    for (char c : value) {
        if (c == ',') ++count;
    }
    return count;
}

void TestPidZeroIgnored() {
    edr::C2BeaconDetector detector(true, 100, 4096, 3, 2);
    edr::Event event =
        NetConnect(0, "C:\\evil\\beacon.exe", "10.0.0.1", "443", 1000);
    detector.Enrich(event);
    C2_CHECK(!HasField(event, edr::field::kC2BeaconScore));
    C2_CHECK(!HasField(event, edr::field::kC2BeaconRepeatConnections));
    C2_CHECK(!HasField(event, edr::field::kC2BeaconDestinations));
    C2_CHECK(!HasField(event, edr::field::kC2BeaconWindowSeconds));
    C2_CHECK(detector.StateCount() == 0);
}

void TestBeaconFlagged() {
    edr::C2BeaconDetector detector(true, 60, 4096, 3, 2);
    const uint64_t base = 100000000000ULL;
    const char* image = "C:\\Windows\\Temp\\beacon.exe";

    /* Endpoint A, twice: repeatCount stays below the threshold. */
    edr::Event a1 =
        NetConnect(1001, image, "10.0.0.1", "1114", base);
    detector.Enrich(a1);
    C2_CHECK(!HasField(a1, edr::field::kC2BeaconScore));
    edr::Event a2 =
        NetConnect(1001, image, "10.0.0.1", "1114", base + 10000000);
    detector.Enrich(a2);
    C2_CHECK(!HasField(a2, edr::field::kC2BeaconScore));

    /* Endpoint B twice: repeatCount is 2, still below 3. */
    edr::Event b1 =
        NetConnect(1001, image, "10.0.0.2", "443", base + 20000000);
    detector.Enrich(b1);
    edr::Event b2 =
        NetConnect(1001, image, "10.0.0.2", "443", base + 30000000);
    detector.Enrich(b2);
    C2_CHECK(!HasField(b2, edr::field::kC2BeaconScore));

    /* Endpoint C first connection: repeatCount still 2. */
    edr::Event c1 =
        NetConnect(1001, image, "10.0.0.3", "443", base + 40000000);
    detector.Enrich(c1);
    C2_CHECK(!HasField(c1, edr::field::kC2BeaconScore));

    /* Endpoint C second connection: repeatCount reaches 3 -> flagged. */
    edr::Event c2 =
        NetConnect(1001, image, "10.0.0.3", "443", base + 50000000);
    detector.Enrich(c2);
    C2_CHECK(HasField(c2, edr::field::kC2BeaconScore));
    C2_CHECK(c2.fields.at(edr::field::kC2BeaconScore) == "60");
    C2_CHECK(c2.fields.at(edr::field::kC2BeaconRepeatConnections) == "3");
    C2_CHECK(CountCommaSeparated(
                 c2.fields.at(edr::field::kC2BeaconDestinations)) == 3);
    C2_CHECK(c2.fields.at(edr::field::kC2BeaconWindowSeconds) == "60");
    C2_CHECK(detector.StateCount() == 1);
}

void TestWindowExpiry() {
    edr::C2BeaconDetector detector(true, 60, 4096, 3, 2);
    const uint64_t base = 200000000000ULL;
    const char* image = "C:\\evil\\beacon.exe";

    /* Build up to a flagged state (A, B, C each twice). */
    edr::Event a1 =
        NetConnect(1001, image, "10.0.0.1", "1114", base);
    detector.Enrich(a1);
    edr::Event a2 =
        NetConnect(1001, image, "10.0.0.1", "1114", base + 10000000);
    detector.Enrich(a2);
    edr::Event b1 =
        NetConnect(1001, image, "10.0.0.2", "443", base + 20000000);
    detector.Enrich(b1);
    edr::Event b2 =
        NetConnect(1001, image, "10.0.0.2", "443", base + 30000000);
    detector.Enrich(b2);
    edr::Event c1 =
        NetConnect(1001, image, "10.0.0.3", "443", base + 40000000);
    detector.Enrich(c1);
    edr::Event c2 =
        NetConnect(1001, image, "10.0.0.3", "443", base + 50000000);
    detector.Enrich(c2);
    C2_CHECK(HasField(c2, edr::field::kC2BeaconScore));

    /* Advance beyond the 60s window: all endpoints expire, the key is
     * dropped, and the flag resets. */
    edr::Event d =
        NetConnect(1001, image, "10.0.0.4", "4444", base + 700000000ULL);
    detector.Enrich(d);
    C2_CHECK(!HasField(d, edr::field::kC2BeaconScore));
    C2_CHECK(detector.StateCount() == 1);

    /* Rebuild the threshold: fields are emitted again only once 3 endpoints
     * each have >= 2 connections. */
    edr::Event d2 =
        NetConnect(1001, image, "10.0.0.4", "4444", base + 710000000ULL);
    detector.Enrich(d2);
    C2_CHECK(!HasField(d2, edr::field::kC2BeaconScore));
    edr::Event e1 =
        NetConnect(1001, image, "10.0.0.5", "4445", base + 720000000ULL);
    detector.Enrich(e1);
    edr::Event e2 =
        NetConnect(1001, image, "10.0.0.5", "4445", base + 730000000ULL);
    detector.Enrich(e2);
    C2_CHECK(!HasField(e2, edr::field::kC2BeaconScore));
    edr::Event f1 =
        NetConnect(1001, image, "10.0.0.6", "6666", base + 740000000ULL);
    detector.Enrich(f1);
    edr::Event f2 =
        NetConnect(1001, image, "10.0.0.6", "6666", base + 750000000ULL);
    detector.Enrich(f2);
    C2_CHECK(HasField(f2, edr::field::kC2BeaconScore));
    C2_CHECK(f2.fields.at(edr::field::kC2BeaconScore) == "60");
    C2_CHECK(f2.fields.at(edr::field::kC2BeaconRepeatConnections) == "3");
}

void TestDisabled() {
    edr::C2BeaconDetector detector(false, 60, 4096, 3, 2);
    edr::Event event =
        NetConnect(1001, "C:\\evil\\beacon.exe", "10.0.0.1", "443", 1000);
    detector.Enrich(event);
    C2_CHECK(!HasField(event, edr::field::kC2BeaconScore));
    C2_CHECK(!HasField(event, edr::field::kC2BeaconRepeatConnections));
    C2_CHECK(!HasField(event, edr::field::kC2BeaconDestinations));
    C2_CHECK(!HasField(event, edr::field::kC2BeaconWindowSeconds));
    C2_CHECK(detector.StateCount() == 0);
}

void TestCapacityEviction() {
    edr::C2BeaconDetector detector(true, 60, 2, 3, 2);
    const uint64_t base = 300000000000ULL;
    for (uint32_t pid = 1; pid <= 3; ++pid) {
        edr::Event event = NetConnect(pid, "C:\\evil\\beacon.exe",
                                      "10.0.0.1", "443",
                                      base + pid * 1000000);
        detector.Enrich(event);
    }
    C2_CHECK(detector.StateCount() <= 2);
}

void TestInspectsAndEndpointFiltering() {
    C2_CHECK(edr::C2BeaconDetector::Inspects(EDR_EVT_NET_CONNECT));
    C2_CHECK(!edr::C2BeaconDetector::Inspects(EDR_EVT_PROCESS_START));

    edr::C2BeaconDetector detector(true, 60, 4096, 3, 2);
    const uint64_t base = 400000000000ULL;

    /* Loopback, empty, and zero-port endpoints are skipped entirely. */
    edr::Event loopback =
        NetConnect(2001, "C:\\evil\\beacon.exe", "127.0.0.1", "443", base);
    detector.Enrich(loopback);
    C2_CHECK(detector.StateCount() == 0);

    edr::Event any =
        NetConnect(2001, "C:\\evil\\beacon.exe", "0.0.0.0", "443",
                   base + 1000000);
    detector.Enrich(any);
    C2_CHECK(detector.StateCount() == 0);

    edr::Event v6Loopback =
        NetConnect(2001, "C:\\evil\\beacon.exe", "::1", "443",
                   base + 2000000);
    detector.Enrich(v6Loopback);
    C2_CHECK(detector.StateCount() == 0);

    edr::Event noPort =
        NetConnect(2001, "C:\\evil\\beacon.exe", "10.0.0.1", "", base + 3000000);
    detector.Enrich(noPort);
    C2_CHECK(detector.StateCount() == 0);

    edr::Event zeroPort =
        NetConnect(2001, "C:\\evil\\beacon.exe", "10.0.0.1", "0",
                   base + 4000000);
    detector.Enrich(zeroPort);
    C2_CHECK(detector.StateCount() == 0);

    edr::Event noIp =
        NetConnect(2001, "C:\\evil\\beacon.exe", "", "443", base + 5000000);
    detector.Enrich(noIp);
    C2_CHECK(detector.StateCount() == 0);

    /* A valid connection creates state. */
    edr::Event valid =
        NetConnect(2001, "C:\\evil\\beacon.exe", "10.0.0.9", "443",
                   base + 6000000);
    detector.Enrich(valid);
    C2_CHECK(detector.StateCount() == 1);
}

} // namespace

void RunC2BeaconDetectorTests() {
    TestPidZeroIgnored();
    TestBeaconFlagged();
    TestWindowExpiry();
    TestDisabled();
    TestCapacityEviction();
    TestInspectsAndEndpointFiltering();
}