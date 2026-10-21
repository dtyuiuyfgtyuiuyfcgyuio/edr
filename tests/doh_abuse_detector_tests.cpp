#include "doh_abuse_detector_tests.h"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <type_traits>

#include <windows.h>

#include "doh_abuse_detector.h"
#include "edr_event.h"
#include "event_bus.h"

namespace {

static_assert(!std::is_copy_constructible<edr::DohAbuseDetector>::value,
              "ordered indexes contain pointers into owning map nodes");
static_assert(!std::is_copy_assignable<edr::DohAbuseDetector>::value,
              "ordered indexes contain pointers into owning map nodes");
static_assert(!std::is_move_constructible<edr::DohAbuseDetector>::value,
              "ordered index pointers are not transferable");
static_assert(!std::is_move_assignable<edr::DohAbuseDetector>::value,
              "ordered index pointers are not transferable");

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
    ev.fields[edr::field::kSource] = "dns_etw";
    ev.fields[edr::field::kEndpointId] = "host-a";
    if (pid != 0 && ts100ns != 0)
        ev.processStartTime100ns = static_cast<uint64_t>(pid) + 1;
    return ev;
}

uint64_t Now100ns() {
    FILETIME now{};
    GetSystemTimePreciseAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) |
           now.dwLowDateTime;
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

void TestStartedAndReportOnlyQueriesDoNotPolluteCompletedQuery() {
    edr::DohAbuseDetector detector(true, 300, 16, 2);
    const uint64_t now = Now100ns();
    edr::Event started = DnsQuery("dns.google", "C:\\Temp\\implant.exe", 8200, now);
    started.fields["dns_phase"] = "started";
    started.fields["dns_event_id"] = "3009";
    started.disposition = edr::EventDisposition::ReportOnly;
    detector.Enrich(started);
    DOH_CHECK(detector.StateCount() == 0);

    edr::Event reportOnly = DnsQuery("dns.google", "C:\\Temp\\implant.exe", 8200, now);
    reportOnly.fields["dns_phase"] = "completed";
    reportOnly.disposition = edr::EventDisposition::ReportOnly;
    detector.Enrich(reportOnly);
    DOH_CHECK(detector.StateCount() == 0);

    edr::Event completed = DnsQuery("dns.google", "C:\\Temp\\implant.exe", 8200, now + 1);
    completed.fields["dns_phase"] = "completed";
    completed.fields["dns_event_id"] = "3008";
    detector.Enrich(completed);
    DOH_CHECK(Field(completed, edr::field::kDohAbuseQueryCount) == "1");
    DOH_CHECK(Field(completed, edr::field::kDohAbuseSignals).find("repeat_queries") == std::string::npos);
}

void TestCompletedAndLegacyUnphasedQueriesRemainSupported() {
    edr::DohAbuseDetector detector(true, 300, 16, 2);
    const uint64_t now = Now100ns();
    edr::Event first = DnsQuery("dns.google", "C:\\Temp\\implant.exe", 8201, now);
    first.fields["dns_phase"] = "completed";
    detector.Enrich(first);
    edr::Event legacy = DnsQuery("dns.google", "C:\\Temp\\implant.exe", 8201, now + 1);
    detector.Enrich(legacy);
    DOH_CHECK(Field(legacy, edr::field::kDohAbuseQueryCount) == "2");
    DOH_CHECK(Field(legacy, edr::field::kDohAbuseSignals).find("repeat_queries") != std::string::npos);
}

void TestProcessInstanceAndScopeAreIsolated() {
    const uint64_t now = Now100ns();
    edr::DohAbuseDetector detector(true, 300, 16, 2);
    edr::Event first = DnsQuery("dns.google", "C:\\Temp\\same.exe", 8300, now);
    detector.Enrich(first);

    edr::Event pidReuse = DnsQuery("dns.google", "C:\\Temp\\same.exe", 8300, now + 1);
    pidReuse.processStartTime100ns = now - 1;
    detector.Enrich(pidReuse);
    DOH_CHECK(Field(pidReuse, edr::field::kDohAbuseQueryCount) == "1");

    edr::Event differentPath = DnsQuery("dns.google", "C:\\Other\\same.exe", 8300, now + 2);
    detector.Enrich(differentPath);
    DOH_CHECK(Field(differentPath, edr::field::kDohAbuseQueryCount) == "1");

    edr::Event differentEndpoint = DnsQuery("dns.google", "C:\\Temp\\same.exe", 8300, now + 3);
    differentEndpoint.fields[edr::field::kEndpointId] = "host-b";
    detector.Enrich(differentEndpoint);
    DOH_CHECK(Field(differentEndpoint, edr::field::kDohAbuseQueryCount) == "1");

    edr::Event differentSource = DnsQuery("dns.google", "C:\\Temp\\same.exe", 8300, now + 4);
    differentSource.source = "sysmon";
    differentSource.fields[edr::field::kSource] = "sysmon";
    detector.Enrich(differentSource);
    DOH_CHECK(Field(differentSource, edr::field::kDohAbuseQueryCount) == "1");
}

void TestInvalidSourceAndOversizedImageOnlyProduceSingleEvidence() {
    edr::DohAbuseDetector detector(true, 300, 16, 2);
    const uint64_t now = Now100ns();
    edr::Event first = DnsQuery("dns.google", "C:\\Temp\\same.exe", 8350, now);
    detector.Enrich(first);

    edr::Event conflict = DnsQuery("dns.google", "C:\\Temp\\same.exe", 8350, now + 1);
    conflict.source = "dns_etw";
    conflict.fields[edr::field::kSource] = "sysmon";
    detector.Enrich(conflict);
    DOH_CHECK(Field(conflict, edr::field::kDohAbuseQueryCount) == "1");
    DOH_CHECK(detector.StateCount() == 1);

    edr::Event longSource = DnsQuery("dns.quad9.net", "C:\\Temp\\same.exe", 8350, now + 2);
    longSource.source = std::string(65, 's');
    longSource.fields[edr::field::kSource] = longSource.source;
    detector.Enrich(longSource);
    DOH_CHECK(Field(longSource, edr::field::kDohAbuseQueryCount) == "1");

    edr::Event longImage = DnsQuery("dns.quad9.net", std::string(4097, 'x'), 8350, now + 3);
    detector.Enrich(longImage);
    DOH_CHECK(Field(longImage, edr::field::kDohAbuseQueryCount) == "1");

    edr::Event nextValid = DnsQuery("dns.google", "C:\\Temp\\same.exe", 8350, now + 4);
    detector.Enrich(nextValid);
    DOH_CHECK(Field(nextValid, edr::field::kDohAbuseQueryCount) == "2");
}

void TestFrequentRehashAndCapacityEvictionKeepStateUsable() {
    edr::DohAbuseDetector detector(true, 300, 16, 2);
    const uint64_t now = Now100ns();
    for (uint32_t i = 0; i < 256; ++i) {
        edr::Event event = DnsQuery("dns.google", "C:\\Temp\\worker.exe",
                                    9000 + i, now + i);
        detector.Enrich(event);
        DOH_CHECK(detector.StateCount() <= 16);
    }
    edr::Event retained = DnsQuery("dns.google", "C:\\Temp\\worker.exe",
                                   9255, now + 1000);
    detector.Enrich(retained);
    DOH_CHECK(Field(retained, edr::field::kDohAbuseQueryCount) == "2");
    DOH_CHECK(detector.StateCount() == 16);
}

void TestUnknownIdentityProducesOnlySingleEventEvidence() {
    edr::DohAbuseDetector detector(true, 300, 16, 1);
    const uint64_t now = Now100ns();
    edr::Event first = DnsQuery("dns.google", "C:\\Temp\\implant.exe", 0, now);
    detector.Enrich(first);
    DOH_CHECK(Field(first, edr::field::kDohAbuseScore) == "60");
    DOH_CHECK(Field(first, edr::field::kDohAbuseSignals).find("repeat_queries") == std::string::npos);
    DOH_CHECK(Field(first, edr::field::kDohAbuseSignals).find("multi_provider") == std::string::npos);
    DOH_CHECK(detector.StateCount() == 0);

    edr::Event second = DnsQuery("dns.quad9.net", "C:\\Temp\\implant.exe", 0, now + 1);
    detector.Enrich(second);
    DOH_CHECK(Field(second, edr::field::kDohAbuseSignals).find("multi_provider") == std::string::npos);
    DOH_CHECK(detector.StateCount() == 0);
}

void TestTimestampGuardsRejectInvalidAndLateEvidence() {
    edr::DohAbuseDetector detector(true, 30, 16, 2);
    const uint64_t now = Now100ns();
    edr::Event zero = DnsQuery("dns.google", "C:\\Temp\\implant.exe", 8400, 0);
    detector.Enrich(zero);
    DOH_CHECK(detector.StateCount() == 0);

    edr::Event futureStart = DnsQuery("dns.google", "C:\\Temp\\implant.exe", 8400, now + 1);
    futureStart.processStartTime100ns = now + 2;
    detector.Enrich(futureStart);
    DOH_CHECK(detector.StateCount() == 0);

    edr::Event future = DnsQuery("dns.google", "C:\\Temp\\implant.exe", 8400, now + 600ULL * 10000000ULL);
    detector.Enrich(future);
    DOH_CHECK(detector.StateCount() == 0);

    edr::Event ordered = DnsQuery("dns.google", "C:\\Temp\\implant.exe", 8400, now + 3);
    detector.Enrich(ordered);
    edr::Event late = DnsQuery("dns.quad9.net", "C:\\Temp\\implant.exe", 8400, now + 2);
    detector.Enrich(late);
    DOH_CHECK(Field(late, edr::field::kDohAbuseQueryCount).empty());
}

void TestSlidingWindowExpiresOldProvidersAndCapacityStaysBounded() {
    edr::DohAbuseDetector detector(true, 10, 1, 2);
    const uint64_t now = Now100ns();
    const char* providers[] = {"dns.quad9.net", "dns.google", "dns.google",
                               "dns.google"};
    const uint64_t seconds[] = {0, 6, 12, 13};
    edr::Event expired;
    for (size_t i = 0; i < 4; ++i) {
        expired = DnsQuery(providers[i], "C:\\Temp\\implant.exe", 8500,
                           now + seconds[i] * 10000000ULL);
        detector.Enrich(expired);
    }
    DOH_CHECK(Field(expired, edr::field::kDohAbuseQueryCount) == "3");
    DOH_CHECK(Field(expired, edr::field::kDohAbuseSignals).find("multi_provider") == std::string::npos);

    edr::Event ordinaryDns = DnsQuery("api.example.com", "C:\\Temp\\implant.exe", 8500,
                                      now + 100ULL * 10000000ULL);
    detector.Enrich(ordinaryDns);
    DOH_CHECK(detector.StateCount() == 1);
    edr::Event wrongType = DnsQuery("dns.google", "C:\\Temp\\implant.exe", 8500,
                                    now + 101ULL * 10000000ULL);
    wrongType.type = EDR_EVT_NET_CONNECT;
    detector.Enrich(wrongType);
    DOH_CHECK(detector.StateCount() == 1);

    edr::Event other = DnsQuery("dns.google", "C:\\Temp\\other.exe", 8501,
                                now + 14ULL * 10000000ULL);
    detector.Enrich(other);
    DOH_CHECK(detector.StateCount() == 1);
}

void TestGlobalObservationBudgetCanEvictCurrentStateSafely() {
    edr::DohAbuseDetector detector(true, 3600, 100, 3);
    const uint64_t now = Now100ns();
    edr::Event target = DnsQuery("dns.google", "C:\\Temp\\target.exe", 8600, now);
    detector.Enrich(target);

    for (uint32_t process = 0; process < 97; ++process) {
        for (uint32_t query = 0; query < 1024; ++query) {
            edr::Event event = DnsQuery(
                "dns.google", "C:\\Temp\\worker.exe", 8700 + process,
                now + 2ULL * 10000000ULL + process);
            detector.Enrich(event);
        }
    }
    for (uint32_t query = 0; query < 671; ++query) {
        edr::Event event = DnsQuery("dns.google", "C:\\Temp\\last.exe", 8800,
                                    now + 3ULL * 10000000ULL);
        detector.Enrich(event);
    }

    // The target's lone older observation is the globally oldest item. Making
    // room for this event may empty and erase its map entry before insertion.
    target = DnsQuery("dns.google", "C:\\Temp\\target.exe", 8600,
                      now + 10000000ULL);
    detector.Enrich(target);
    DOH_CHECK(Field(target, edr::field::kDohAbuseQueryCount) == "1");
    DOH_CHECK(detector.StateCount() <= 100);
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
    TestStartedAndReportOnlyQueriesDoNotPolluteCompletedQuery();
    TestCompletedAndLegacyUnphasedQueriesRemainSupported();
    TestProcessInstanceAndScopeAreIsolated();
    TestInvalidSourceAndOversizedImageOnlyProduceSingleEvidence();
    TestFrequentRehashAndCapacityEvictionKeepStateUsable();
    TestUnknownIdentityProducesOnlySingleEventEvidence();
    TestTimestampGuardsRejectInvalidAndLateEvidence();
    TestSlidingWindowExpiresOldProvidersAndCapacityStaysBounded();
    TestGlobalObservationBudgetCanEvictCurrentStateSafely();
}
