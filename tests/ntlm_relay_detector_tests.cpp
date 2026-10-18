#include "ntlm_relay_detector_tests.h"

#include <stdexcept>
#include <string>
#include <cstdlib>

#include "edr_event.h"
#include "event_bus.h"
#include "ntlm_relay_detector.h"

namespace {

#define NR_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond)
        throw std::runtime_error(
            "ntlm relay test failed at line " +
            std::to_string(line) + ": " + expr);
}

edr::Event Logon(const std::string& user, const std::string& srcIp,
                  const std::string& srcWs, const std::string& authPkg,
                  uint64_t ts) {
    edr::Event ev;
    ev.type = EDR_EVT_LOGON;
    ev.ts100ns = ts;
    ev.fields[edr::field::kLogonType] = "3";
    ev.fields[edr::field::kTargetUser] = user;
    ev.fields[edr::field::kSrcIp] = srcIp;
    ev.fields[edr::field::kSourceWorkstation] = srcWs;
    ev.fields[edr::field::kAuthPackage] = authPkg;
    return ev;
}

void TestMultipleSources() {
    edr::NtlmRelayDetector det(true, 600, 4096, 3);
    const uint64_t base = 1000000000ULL;
    det.Enrich(Logon("admin", "10.0.0.5", "WS1", "NTLM", base));
    det.Enrich(Logon("admin", "10.0.0.6", "WS2", "NTLM", base + 10000000));
    edr::Event ev = Logon("admin", "10.0.0.7", "WS3", "NTLM",
                          base + 20000000);
    det.Enrich(ev);
    NR_CHECK(ev.fields.count(edr::field::kNtlmRelayScore) > 0);
    const uint32_t score = static_cast<uint32_t>(
        std::atoi(ev.fields.at(edr::field::kNtlmRelayScore).c_str()));
    NR_CHECK(score >= 55);
    /* 30 (sources) + 20 (workstations) + 15 (events) + 15 (correlation) = 80,
     * which crosses the MALICIOUS band. */
    NR_CHECK(ev.fields.at(edr::field::kNtlmRelayVerdict) == "MALICIOUS");
    NR_CHECK(ev.fields.at(edr::field::kNtlmRelaySignals).find("multiple_sources") !=
             std::string::npos);
}

void TestBurstLogons() {
    edr::NtlmRelayDetector det(true, 600, 4096, 3);
    const uint64_t base = 2000000000ULL;
    edr::Event ev;
    for (int i = 0; i < 5; ++i) {
        ev = Logon("svc", "10.0.0.5", "WS1", "NTLM",
                   base + i * 10000000ULL);
        det.Enrich(ev);
    }
    NR_CHECK(ev.fields.count(edr::field::kNtlmRelayScore) > 0);
    NR_CHECK(ev.fields.at(edr::field::kNtlmRelaySignals).find("burst_logons") !=
             std::string::npos);
}

void TestNonNtlmLogonNoStamp() {
    edr::NtlmRelayDetector det(true, 600, 4096, 3);
    const uint64_t base = 3000000000ULL;
    edr::Event ev = Logon("admin", "10.0.0.5", "WS1", "Kerberos", base);
    ev.fields[edr::field::kLogonType] = "3";
    det.Enrich(ev);
    NR_CHECK(ev.fields.find(edr::field::kNtlmRelayScore) == ev.fields.end());
}

void TestInteractiveLogonNoStamp() {
    edr::NtlmRelayDetector det(true, 600, 4096, 3);
    const uint64_t base = 4000000000ULL;
    edr::Event ev = Logon("admin", "10.0.0.5", "WS1", "NTLM", base);
    ev.fields[edr::field::kLogonType] = "2";
    det.Enrich(ev);
    NR_CHECK(ev.fields.find(edr::field::kNtlmRelayScore) == ev.fields.end());
}

void TestDisabledNoStamp() {
    edr::NtlmRelayDetector det(false, 600, 4096, 3);
    const uint64_t base = 5000000000ULL;
    edr::Event ev = Logon("admin", "10.0.0.5", "WS1", "NTLM", base);
    det.Enrich(ev);
    NR_CHECK(ev.fields.find(edr::field::kNtlmRelayScore) == ev.fields.end());
}

} // namespace

void RunNtlmRelayDetectorTests() {
    TestMultipleSources();
    TestBurstLogons();
    TestNonNtlmLogonNoStamp();
    TestInteractiveLogonNoStamp();
    TestDisabledNoStamp();
}
