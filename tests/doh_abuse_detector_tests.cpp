#include "doh_abuse_detector_tests.h"

#include <cstdint>
#include <stdexcept>
#include <string>

#include "doh_abuse_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

#define DOH_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond) {
        throw std::runtime_error(
            "doh abuse detector test failed at line " +
            std::to_string(line) + ": " + expr);
    }
}

edr::Event DnsQuery(const std::string& name, const std::string& image,
                    uint32_t pid, uint64_t ts100ns) {
    edr::Event ev;
    ev.type = EDR_EVT_DNS_QUERY;
    ev.pid = pid;
    ev.ts100ns = ts100ns;
    ev.fields[edr::field::kType] = "DNS_QUERY";
    ev.fields[edr::field::kDnsQueryName] = name;
    ev.fields[edr::field::kImage] = image;
    return ev;
}

std::string Field(const edr::Event& ev, const char* name) {
    auto found = ev.fields.find(name);
    return found == ev.fields.end() ? std::string() : found->second;
}

/* Non-browser tool resolving a DoH endpoint: endpoint(40) + non_browser(20)
 * = 60 -> SUSPICIOUS on the first query. */
void TestSingleNonBrowserQuerySuspicious() {
    edr::DohAbuseDetector detector(true, 300, 1024, 3);
    edr::Event ev = DnsQuery("cloudflare-dns.com",
                             "C:\\Temp\\implant.exe", 8100, 1000000000ULL);
    detector.Enrich(ev);
    DOH_CHECK(Field(ev, edr::field::kDohAbuseVerdict) == "SUSPICIOUS");
    DOH_CHECK(Field(ev, edr::field::kDohAbuseScore) == "60");
    DOH_CHECK(Field(ev, edr::field::kDohAbuseSignals)
                 .find("non_browser") != std::string::npos);
    DOH_CHECK(Field(ev, edr::field::kDohAbuseEndpoints)
                 .find("cloudflare-dns.com") != std::string::npos);
}

/* Repeated queries cross into MALICIOUS: +20 repeat => 80. */
void TestRepeatedQueriesMalicious() {
    edr::DohAbuseDetector detector(true, 300, 1024, 3);
    for (uint64_t i = 0; i < 3; ++i) {
        edr::Event ev = DnsQuery("dns.google", "C:\\Temp\\implant.exe",
                                 8101, 2000000000ULL + i * 10000000ULL);
        detector.Enrich(ev);
        if (i == 2) {
            DOH_CHECK(Field(ev, edr::field::kDohAbuseVerdict) == "MALICIOUS");
            DOH_CHECK(Field(ev, edr::field::kDohAbuseSignals)
                         .find("repeat_queries") != std::string::npos);
            DOH_CHECK(Field(ev, edr::field::kDohAbuseQueryCount) == "3");
        }
    }
}

/* Multi-provider bootstrap burst: endpoint(40)+repeat(20)+multi(15)
 * +non_browser(20) = 95 -> MALICIOUS. */
void TestMultiProviderBurst() {
    edr::DohAbuseDetector detector(true, 300, 1024, 2);
    const char* kNames[] = {"cloudflare-dns.com", "dns.quad9.net",
                            "doh.mullvad.net"};
    edr::Event last;
    for (uint64_t i = 0; i < 3; ++i) {
        last = DnsQuery(kNames[i], "C:\\Tools\\tunneler.exe", 8102,
                        3000000000ULL + i * 10000000ULL);
        detector.Enrich(last);
    }
    DOH_CHECK(Field(last, edr::field::kDohAbuseVerdict) == "MALICIOUS");
    DOH_CHECK(Field(last, edr::field::kDohAbuseSignals)
                 .find("multi_provider") != std::string::npos);
}

/* Browser lookups of a DoH provider are not flagged non-browser:
 * endpoint(40) only -> below threshold, no verdict. */
void TestBrowserNotFlagged() {
    edr::DohAbuseDetector detector(true, 300, 1024, 3);
    edr::Event ev = DnsQuery("chrome.cloudflare-dns.com",
                             "C:\\Program Files\\Google\\Chrome\\Application"
                             "\\chrome.exe",
                             8103, 4000000000ULL);
    detector.Enrich(ev);
    DOH_CHECK(Field(ev, edr::field::kDohAbuseVerdict).empty());
}

/* Non-DoH domains are ignored entirely. */
void TestOrdinaryDomainIgnored() {
    edr::DohAbuseDetector detector(true, 300, 1024, 3);
    edr::Event ev = DnsQuery("api.example.com", "C:\\Temp\\implant.exe",
                             8104, 5000000000ULL);
    detector.Enrich(ev);
    DOH_CHECK(Field(ev, edr::field::kDohAbuseScore).empty());
    DOH_CHECK(detector.StateCount() == 0);
}

/* FQDN trailing dot is normalized and still matched. */
void TestFqdnTrailingDotMatched() {
    edr::DohAbuseDetector detector(true, 300, 1024, 3);
    edr::Event ev = DnsQuery("dns.google.", "C:\\Temp\\implant.exe",
                             8105, 6000000000ULL);
    detector.Enrich(ev);
    DOH_CHECK(Field(ev, edr::field::kDohAbuseSignals)
                 .find("doh_endpoint") != std::string::npos);
}

/* Disabled detector never enriches. */
void TestDisabledDetector() {
    edr::DohAbuseDetector detector(false, 300, 1024, 3);
    edr::Event ev = DnsQuery("dns.google", "C:\\Temp\\implant.exe",
                             8106, 7000000000ULL);
    detector.Enrich(ev);
    DOH_CHECK(Field(ev, edr::field::kDohAbuseScore).empty());
}

} // namespace

void RunDohAbuseDetectorTests() {
    TestSingleNonBrowserQuerySuspicious();
    TestRepeatedQueriesMalicious();
    TestMultiProviderBurst();
    TestBrowserNotFlagged();
    TestOrdinaryDomainIgnored();
    TestFqdnTrailingDotMatched();
    TestDisabledDetector();
}
