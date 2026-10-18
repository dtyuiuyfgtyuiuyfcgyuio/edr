#include "cryptominer_detector_tests.h"

#include <stdexcept>
#include <string>
#include <cstdlib>

#include "edr_event.h"
#include "event_bus.h"
#include "cryptominer_detector.h"

namespace {

#define CM_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond)
        throw std::runtime_error(
            "cryptominer test failed at line " +
            std::to_string(line) + ": " + expr);
}

edr::Event ProcStart(const std::string& image, uint32_t pid, uint64_t ts) {
    edr::Event ev;
    ev.type = EDR_EVT_PROCESS_START;
    ev.pid = pid;
    ev.ts100ns = ts;
    ev.fields[edr::field::kImage] = image;
    return ev;
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

void TestKnownMinerBinary() {
    edr::CryptominerDetector det(true, 600, 2048);
    const uint64_t base = 1000000000ULL;
    edr::Event ev = ProcStart("C:\\xmrig\\xmrig.exe", 9001, base);
    det.Enrich(ev);
    CM_CHECK(ev.fields.count(edr::field::kCryptoMinerScore) > 0);
    CM_CHECK(ev.fields.at(edr::field::kCryptoMinerScore) == "45");
    CM_CHECK(ev.fields.at(edr::field::kCryptoMinerSignals).find("miner_binary") !=
             std::string::npos);
}

void TestMiningPoolDomain() {
    edr::CryptominerDetector det(true, 600, 2048);
    const uint64_t base = 2000000000ULL;
    edr::Event ev = DnsQuery("pool.ethermine.org", 9002, base);
    det.Enrich(ev);
    CM_CHECK(ev.fields.count(edr::field::kCryptoMinerScore) > 0);
    CM_CHECK(ev.fields.at(edr::field::kCryptoMinerScore) == "30");
    CM_CHECK(ev.fields.at(edr::field::kCryptoMinerPoolDomains).find("ethermine") !=
             std::string::npos);
}

void TestStratumPort() {
    edr::CryptominerDetector det(true, 600, 2048);
    const uint64_t base = 3000000000ULL;
    edr::Event ev = NetConnect("203.0.113.10", "3333", 9003, base);
    det.Enrich(ev);
    CM_CHECK(ev.fields.count(edr::field::kCryptoMinerScore) > 0);
    /* Stratum port (25) also records the destination as a pool IP (+20). */
    CM_CHECK(ev.fields.at(edr::field::kCryptoMinerScore) == "45");
    CM_CHECK(ev.fields.at(edr::field::kCryptoMinerSignals).find("stratum_port") !=
             std::string::npos);
}

void TestMultiSignalCorrelation() {
    edr::CryptominerDetector det(true, 600, 2048);
    const uint64_t base = 4000000000ULL;
    det.Enrich(ProcStart("C:\\xmrig\\xmrig.exe", 9004, base));
    det.Enrich(DnsQuery("pool.ethermine.org", 9004, base + 10000000));
    edr::Event ev = NetConnect("203.0.113.10", "3333", 9004,
                               base + 20000000);
    det.Enrich(ev);
    const uint32_t score = static_cast<uint32_t>(
        std::atoi(ev.fields.at(edr::field::kCryptoMinerScore).c_str()));
    CM_CHECK(score >= 75);
    CM_CHECK(ev.fields.at(edr::field::kCryptoMinerVerdict) == "MALICIOUS");
}

void TestNonMinerBinaryNoStamp() {
    edr::CryptominerDetector det(true, 600, 2048);
    const uint64_t base = 5000000000ULL;
    edr::Event ev = ProcStart("C:\\Windows\\System32\\notepad.exe", 9005, base);
    det.Enrich(ev);
    CM_CHECK(ev.fields.find(edr::field::kCryptoMinerScore) == ev.fields.end());
}

void TestDisabledNoStamp() {
    edr::CryptominerDetector det(false, 600, 2048);
    const uint64_t base = 6000000000ULL;
    edr::Event ev = ProcStart("C:\\xmrig\\xmrig.exe", 9006, base);
    det.Enrich(ev);
    CM_CHECK(ev.fields.find(edr::field::kCryptoMinerScore) == ev.fields.end());
}

} // namespace

void RunCryptominerDetectorTests() {
    TestKnownMinerBinary();
    TestMiningPoolDomain();
    TestStratumPort();
    TestMultiSignalCorrelation();
    TestNonMinerBinaryNoStamp();
    TestDisabledNoStamp();
}
