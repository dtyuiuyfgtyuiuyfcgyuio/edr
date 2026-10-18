#include "data_exfiltration_detector_tests.h"

#include <stdexcept>
#include <string>
#include <cstdlib>

#include "edr_event.h"
#include "event_bus.h"
#include "data_exfiltration_detector.h"

namespace {

#define DE_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond)
        throw std::runtime_error(
            "data exfiltration test failed at line " +
            std::to_string(line) + ": " + expr);
}

edr::Event NetConnect(const std::string& ip, const std::string& port,
                      uint32_t pid, uint64_t ts) {
    edr::Event ev;
    ev.type = EDR_EVT_NET_CONNECT;
    ev.pid = pid;
    ev.ts100ns = ts;
    ev.fields[edr::field::kDstIp] = ip;
    ev.fields[edr::field::kDstPort] = port;
    return ev;
}

edr::Event DnsQuery(const std::string& name, uint32_t pid, uint64_t ts) {
    edr::Event ev;
    ev.type = EDR_EVT_DNS_QUERY;
    ev.pid = pid;
    ev.ts100ns = ts;
    ev.fields[edr::field::kDnsQueryName] = name;
    return ev;
}

void TestExternalConnection() {
    edr::DataExfiltrationDetector det(true, 300, 4096, 50);
    const uint64_t base = 1000000000ULL;
    edr::Event ev = NetConnect("203.0.113.50", "443", 6001, base);
    det.Enrich(ev);
    DE_CHECK(ev.fields.count(edr::field::kDataExfilScore) > 0);
    DE_CHECK(ev.fields.at(edr::field::kDataExfilScore) == "5");
}

void TestMultipleExternalConnections() {
    edr::DataExfiltrationDetector det(true, 300, 4096, 50);
    const uint64_t base = 2000000000ULL;
    for (int i = 0; i < 5; ++i) {
        edr::Event ev = NetConnect("203.0.113." + std::to_string(50 + i),
                                   "443", 6002, base + i * 10000000ULL);
        det.Enrich(ev);
    }
    edr::Event last = NetConnect("203.0.113.99", "443", 6002,
                                 base + 6 * 10000000ULL);
    det.Enrich(last);
    DE_CHECK(last.fields.at(edr::field::kDataExfilScore) == "25");
    /* Score 25 stays below the 55 alerting band, so no verdict is stamped
     * (the detector only emits a verdict at SUSPICIOUS/MALICIOUS). */
    DE_CHECK(last.fields.find(edr::field::kDataExfilVerdict) ==
             last.fields.end());
}

void TestDnsTunneling() {
    edr::DataExfiltrationDetector det(true, 300, 4096, 10);
    const uint64_t base = 3000000000ULL;
    /* Exfil staging is multi-signal: external beacons plus a burst of
     * long, high-entropy tunneled labels from the same process. DNS volume
     * alone scores below the alerting band by design. */
    edr::Event ev;
    for (int i = 0; i < 5; ++i) {
        ev = NetConnect("203.0.113.7" + std::to_string(i % 3), "443",
                        6003, base + i * 10000000ULL);
        det.Enrich(ev);
    }
    for (int i = 0; i < 10; ++i) {
        std::string label;
        for (int j = 0; j < 32; ++j)
            label += static_cast<char>('a' + ((i * 7 + j * 11) % 26));
        ev = DnsQuery(label + ".evil.com", 6003,
                      base + (100 + i) * 10000000ULL);
        det.Enrich(ev);
    }
    const std::string scoreStr = ev.fields.at(edr::field::kDataExfilScore);
    const uint32_t score = static_cast<uint32_t>(std::atoi(scoreStr.c_str()));
    DE_CHECK(score >= 55);
    /* 25 (connections) + 40 (tunnel burst) + 15 (multi-signal) = 80. */
    DE_CHECK(ev.fields.at(edr::field::kDataExfilVerdict) == "MALICIOUS");
}

void TestPrivateIpNoStamp() {
    edr::DataExfiltrationDetector det(true, 300, 4096, 50);
    const uint64_t base = 4000000000ULL;
    edr::Event ev = NetConnect("192.168.1.50", "443", 6004, base);
    det.Enrich(ev);
    DE_CHECK(ev.fields.find(edr::field::kDataExfilScore) == ev.fields.end());
}

void TestDisabledNoStamp() {
    edr::DataExfiltrationDetector det(false, 300, 4096, 50);
    const uint64_t base = 5000000000ULL;
    edr::Event ev = NetConnect("203.0.113.50", "443", 6005, base);
    det.Enrich(ev);
    DE_CHECK(ev.fields.find(edr::field::kDataExfilScore) == ev.fields.end());
}

} // namespace

void RunDataExfiltrationDetectorTests() {
    TestExternalConnection();
    TestMultipleExternalConnections();
    TestDnsTunneling();
    TestPrivateIpNoStamp();
    TestDisabledNoStamp();
}
