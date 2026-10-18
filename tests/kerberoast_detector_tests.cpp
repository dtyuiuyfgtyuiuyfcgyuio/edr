/*
 * kerberoast_detector_tests.cpp - Unit tests for KerberoastDetector.
 */
#include "kerberoast_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "config.h"
#include "edr_event.h"
#include "event_bus.h"
#include "kerberoast_detector.h"
#include "rule_engine.h"
#include "security_log_parser.h"

namespace {

#define KR_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error(
            "kerberoast detector test failed at line " +
            std::to_string(line) + ": " + expression);
    }
}

const char* ProductionRulesPath() {
    return GetFileAttributesA("..\\rules\\rules.json") !=
                   INVALID_FILE_ATTRIBUTES
        ? "..\\rules\\rules.json"
        : "rules\\rules.json";
}

bool Has(const std::vector<std::string>& hits, const char* id) {
    return std::find(hits.begin(), hits.end(), id) != hits.end();
}

bool HasField(const edr::Event& event, const char* name) {
    return event.fields.find(name) != event.fields.end();
}

edr::Event Tgs(const char* srcIp, const char* requester,
               const char* service, uint64_t ts100ns,
               const char* encryption = "0x17",
               const char* failure = "0x0") {
    edr::Event event;
    event.type = EDR_EVT_LOGON;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "LOGON";
    event.fields[edr::field::kOperationType] = "TGS_REQUEST";
    if (srcIp) event.fields[edr::field::kSrcIp] = srcIp;
    if (requester) event.fields[edr::field::kTargetUser] = requester;
    event.fields[edr::field::kTargetDomain] = "CORP.LOCAL";
    if (service) event.fields[edr::field::kTgsServiceName] = service;
    if (encryption)
        event.fields[edr::field::kTgsTicketEncryptionType] = encryption;
    if (failure) event.fields[edr::field::kTgsFailureCode] = failure;
    return event;
}

void TestInspectsDisabledAndEligibility() {
    KR_CHECK(edr::KerberoastDetector::Inspects(EDR_EVT_LOGON));
    KR_CHECK(!edr::KerberoastDetector::Inspects(EDR_EVT_NET_CONNECT));

    edr::KerberoastDetector disabled(false, 300, 16, 3, 60, 16);
    edr::Event value = Tgs("10.0.0.5", "alice", "MSSQLSvc/sql", 100000000000ULL);
    disabled.Enrich(value);
    KR_CHECK(!HasField(value, edr::field::kKerberoastScore));
    KR_CHECK(disabled.StateCount() == 0);

    edr::KerberoastDetector detector(true, 300, 16, 2, 60, 16);
    for (edr::Event event : {
             Tgs("10.0.0.5", "alice", "svc/a", 100000000000ULL, "0x12"),
             Tgs("10.0.0.5", "alice", "svc/b", 101000000000ULL, "0x17", "0x1"),
             Tgs("10.0.0.5", "alice", "krbtgt", 102000000000ULL),
             Tgs("10.0.0.5", "alice", "SERVER01$", 103000000000ULL),
             Tgs("10.0.0.5", "HOST01$@CORP.LOCAL", "svc/c", 104000000000ULL),
             Tgs("10.0.0.5", "alice", "SERVER02$@CORP.LOCAL", 105000000000ULL),
             Tgs(nullptr, nullptr, "svc/d", 106000000000ULL)}) {
        detector.Enrich(event);
        KR_CHECK(!HasField(event, edr::field::kKerberoastScore));
    }
    KR_CHECK(detector.StateCount() == 0);
}

void TestDistinctServicesAndThreshold() {
    const uint64_t base = 200000000000ULL;
    edr::KerberoastDetector detector(true, 300, 16, 3, 60, 16);

    /* Duplicate requests for one SPN do not inflate the distinct count. */
    for (int i = 0; i < 4; ++i) {
        edr::Event duplicate = Tgs("10.0.0.6", "alice",
                                   "MSSQLSvc/sql01:1433",
                                   base + i * 10000000ULL);
        detector.Enrich(duplicate);
        KR_CHECK(!HasField(duplicate, edr::field::kKerberoastScore));
    }

    edr::Event second = Tgs("10.0.0.6", "alice", "HTTP/web01",
                            base + 50000000ULL);
    detector.Enrich(second);
    KR_CHECK(!HasField(second, edr::field::kKerberoastScore));

    edr::Event third = Tgs("10.0.0.6", "alice", "LDAP/app01",
                           base + 60000000ULL, "23", "0");
    detector.Enrich(third);
    KR_CHECK(third.fields.at(edr::field::kKerberoastScore) == "45");
    KR_CHECK(third.fields.at(edr::field::kKerberoastServiceCount) == "3");
    KR_CHECK(third.fields.at(edr::field::kKerberoastRequester) ==
             "corp.local\\alice");
    KR_CHECK(third.fields.at(edr::field::kKerberoastSrcIp) == "10.0.0.6");
    KR_CHECK(third.fields.at(edr::field::kKerberoastWindowSeconds) == "300");
    const std::string services =
        third.fields.at(edr::field::kKerberoastServices);
    KR_CHECK(services.find("mssqlsvc/sql01:1433") != std::string::npos);
    KR_CHECK(services.find("http/web01") != std::string::npos);
    KR_CHECK(services.find("ldap/app01") != std::string::npos);
}

void TestRequesterIsolationExpiryAndBounds() {
    const uint64_t base = 300000000000ULL;
    edr::KerberoastDetector detector(true, 60, 2, 2, 0, 2);

    edr::Event one = Tgs("10.0.0.7", "alice", "svc/a", base);
    detector.Enrich(one);
    edr::Event other = Tgs("10.0.0.7", "bob", "svc/b",
                           base + 10000000ULL);
    detector.Enrich(other);
    KR_CHECK(!HasField(other, edr::field::kKerberoastScore));

    /* The service cap rotates old SPNs and remains bounded. */
    edr::Event two = Tgs("10.0.0.7", "alice", "svc/b",
                         base + 20000000ULL);
    detector.Enrich(two);
    KR_CHECK(HasField(two, edr::field::kKerberoastScore));
    edr::Event three = Tgs("10.0.0.7", "alice", "svc/c",
                           base + 30000000ULL);
    detector.Enrich(three);
    KR_CHECK(detector.ServiceCount("10.0.0.7", "CORP.LOCAL", "alice") <= 2);

    /* A third requester evicts one of two requester states. */
    edr::Event thirdRequester = Tgs("10.0.0.8", "charlie", "svc/a",
                                    base + 40000000ULL);
    detector.Enrich(thirdRequester);
    KR_CHECK(detector.StateCount() <= 2);

    /* Individual SPNs expire from the rolling window. */
    edr::KerberoastDetector expiring(true, 60, 4, 2, 0, 8);
    edr::Event old = Tgs("10.0.0.9", "alice", "svc/old", base);
    expiring.Enrich(old);
    edr::Event fresh = Tgs("10.0.0.9", "alice", "svc/fresh",
                           base + 700000000ULL);
    expiring.Enrich(fresh);
    KR_CHECK(!HasField(fresh, edr::field::kKerberoastScore));
}

void TestOrderingCooldownEscalationAndNormalization() {
    const uint64_t base = 400000000000ULL;

    /* Timestamp rollback is rejected before mutation. */
    edr::KerberoastDetector ordered(true, 300, 8, 3, 300, 16);
    edr::Event first = Tgs("10.0.0.11", "alice", "svc/a", base);
    ordered.Enrich(first);
    edr::Event future = Tgs("10.0.0.11", "alice", "svc/c",
                            base + 30 * 10000000ULL);
    ordered.Enrich(future);
    edr::Event late = Tgs("10.0.0.11", "alice", "svc/b",
                          base + 20 * 10000000ULL);
    ordered.Enrich(late);
    KR_CHECK(!HasField(late, edr::field::kKerberoastScore));
    KR_CHECK(ordered.ServiceCount("10.0.0.11", "CORP.LOCAL", "alice") == 2);
    edr::Event crossing = Tgs("10.0.0.11", "alice", "svc/b",
                              base + 40 * 10000000ULL);
    ordered.Enrich(crossing);
    KR_CHECK(HasField(crossing, edr::field::kKerberoastScore));

    /* Another requester's skewed timestamp cannot purge this key. */
    edr::KerberoastDetector isolated(true, 60, 8, 2, 300, 16);
    edr::Event a1 = Tgs("10.0.0.12", "alice", "svc/a", base);
    isolated.Enrich(a1);
    edr::Event skew = Tgs("10.0.0.13", "bob", "svc/x",
                          base + 86400ULL * 10000000ULL);
    isolated.Enrich(skew);
    edr::Event a2 = Tgs("10.0.0.12", "alice", "svc/b",
                        base + 10 * 10000000ULL);
    isolated.Enrich(a2);
    KR_CHECK(HasField(a2, edr::field::kKerberoastScore));

    /* Zero dedup emits on every eligible threshold event. */
    edr::KerberoastDetector noCooldown(true, 300, 8, 2, 0, 16);
    edr::Event d1 = Tgs("10.0.0.14", "alice", "svc/a", base);
    noCooldown.Enrich(d1);
    edr::Event d2 = Tgs("10.0.0.14", "alice", "svc/b",
                        base + 10000000ULL);
    noCooldown.Enrich(d2);
    KR_CHECK(HasField(d2, edr::field::kKerberoastScore));
    edr::Event duplicate = Tgs("10.0.0.14", "alice", "svc/b",
                               base + 20000000ULL);
    noCooldown.Enrich(duplicate);
    KR_CHECK(HasField(duplicate, edr::field::kKerberoastScore));

    /* Cooldown still permits a meaningful second threshold of evidence. */
    edr::KerberoastDetector escalation(true, 300, 8, 2, 300, 16);
    for (int i = 0; i < 4; ++i) {
        const std::string service = "svc/" + std::to_string(i);
        edr::Event value = Tgs("10.0.0.15", "alice", service.c_str(),
                               base + i * 10000000ULL);
        escalation.Enrich(value);
        if (i == 1 || i == 3)
            KR_CHECK(HasField(value, edr::field::kKerberoastScore));
        else
            KR_CHECK(!HasField(value, edr::field::kKerberoastScore));
    }

    /* Common realm suffix spelling and IPv4-mapped input canonicalize. */
    edr::KerberoastDetector canonical(true, 300, 8, 2, 300, 16);
    edr::Event c1 = Tgs("::ffff:10.0.0.16", "ALICE@CORP.LOCAL",
                        "MSSQLSvc/sql01:1433@CORP.LOCAL", base);
    canonical.Enrich(c1);
    edr::Event c2 = Tgs("10.0.0.16", "alice", "HTTP/web01",
                        base + 10000000ULL);
    canonical.Enrich(c2);
    KR_CHECK(HasField(c2, edr::field::kKerberoastScore));
    KR_CHECK(c2.fields.at(edr::field::kKerberoastSrcIp) == "10.0.0.16");
}

void TestRealisticParserIntegrationAndBounds() {
    auto xml = [](const wchar_t* user, const wchar_t* service,
                  const wchar_t* status) {
        return std::wstring(
            L"<Event><System><EventID>4769</EventID>"
            L"<TimeCreated SystemTime='2026-07-30T10:00:00.1234567Z'/>"
            L"</System><EventData><Data Name='TargetUserName'>") + user +
            L"</Data><Data Name='TargetDomainName'>CORP.LOCAL</Data>"
            L"<Data Name='ServiceName'>" + service +
            L"</Data><Data Name='ServiceSid'>S-1-5-21-1002</Data>"
            L"<Data Name='TicketEncryptionType'>0x17</Data>"
            L"<Data Name='IpAddress'>::ffff:10.0.0.17</Data>"
            L"<Data Name='Status'>" + status +
            L"</Data></EventData></Event>";
    };

    edr::KerberoastDetector detector(true, 300, 8, 2, 300, 16);
    edr::Event failed;
    KR_CHECK(edr::ParseSecurityLogXml(
        xml(L"user@CORP.LOCAL", L"HTTP/failed", L"0x1"), failed));
    detector.Enrich(failed);
    KR_CHECK(detector.StateCount() == 0);

    edr::Event one;
    KR_CHECK(edr::ParseSecurityLogXml(
        xml(L"user@CORP.LOCAL", L"MSSQLSvc/sql01:1433", L"0x0"), one));
    detector.Enrich(one);
    edr::Event two;
    KR_CHECK(edr::ParseSecurityLogXml(
        xml(L"user@CORP.LOCAL", L"HTTP/web01", L"0x0"), two));
    two.ts100ns += 10000000ULL; /* Distinct source time for monotonic policy. */
    detector.Enrich(two);
    KR_CHECK(two.fields.at(edr::field::kKerberoastServiceCount) == "2");
    KR_CHECK(two.fields.at(edr::field::kKerberoastRequester) ==
             "corp.local\\user");
    KR_CHECK(two.fields.at(edr::field::kKerberoastSrcIp) == "10.0.0.17");

    const std::string longIp(65, '1');
    const std::string longUser(257, 'u');
    const std::string longService(513, 's');
    edr::KerberoastDetector bounded(true, 300, 8, 2, 0, 16);
    for (edr::Event value : {
             Tgs(longIp.c_str(), "alice", "svc/a", 500000000000ULL),
             Tgs("10.0.0.18", longUser.c_str(), "svc/b", 501000000000ULL),
             Tgs("10.0.0.18", "alice", longService.c_str(), 502000000000ULL),
             Tgs("::ffff:127.0.0.1", "alice", "svc/c", 503000000000ULL)}) {
        bounded.Enrich(value);
        KR_CHECK(!HasField(value, edr::field::kKerberoastScore));
    }
    KR_CHECK(bounded.StateCount() == 0);

    edr::KerberoastDetector summary(true, 300, 8, 2, 0, 16);
    for (int i = 0; i < 16; ++i) {
        const std::string service = "svc/" + std::to_string(i) +
            std::string(480, 's');
        edr::Event value = Tgs("10.0.0.19", "alice", service.c_str(),
                               600000000000ULL + i * 10000000ULL);
        summary.Enrich(value);
        if (i >= 1) {
            KR_CHECK(value.fields.at(edr::field::kKerberoastServices).size()
                     <= 4096);
        }
    }
}

void TestConfigStrictAtomic() {
    const char* path = "edr-native-kerberoast-config.json";
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"kerberoast_burst":{"enable":true,"window_seconds":600,"state_capacity":512,"min_service_count":8,"dedup_seconds":300,"max_services_per_requester":64}})";
    }
    edr::Config config;
    std::string error;
    KR_CHECK(edr::LoadConfigFile(path, config, error));
    KR_CHECK(config.kerberoastBurstEnable);
    KR_CHECK(config.kerberoastBurstWindowSeconds == 600);
    KR_CHECK(config.kerberoastBurstStateCapacity == 512);
    KR_CHECK(config.kerberoastBurstMinServiceCount == 8);
    KR_CHECK(config.kerberoastBurstDedupSeconds == 300);
    KR_CHECK(config.kerberoastBurstMaxServicesPerRequester == 64);

    for (const char* invalid : {
             R"({"kerberoast_burst":true})",
             R"({"kerberoast_burst":{"unknown":1}})",
             R"({"kerberoast_burst":{"min_service_count":1}})",
             R"({"kerberoast_burst":{"state_capacity":63}})",
             R"({"kerberoast_burst":{"max_services_per_requester":3,"min_service_count":4}})"}) {
        std::ofstream out(path, std::ios::binary);
        out << invalid;
        out.close();
        edr::Config unchanged;
        unchanged.kerberoastBurstEnable = true;
        unchanged.kerberoastBurstMinServiceCount = 99;
        KR_CHECK(!edr::LoadConfigFile(path, unchanged, error));
        KR_CHECK(unchanged.kerberoastBurstEnable);
        KR_CHECK(unchanged.kerberoastBurstMinServiceCount == 99);
    }
    DeleteFileA(path);
}

void TestProductionRule() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) { hits.push_back(alert.ruleId); });

    edr::Event event = Tgs("10.0.0.10", "alice", "svc/a", 0);
    event.fields[edr::field::kKerberoastScore] = "75";
    event.fields[edr::field::kKerberoastServiceCount] = "5";
    engine.OnEvent(event);
    KR_CHECK(Has(hits, "EDR-254"));

    hits.clear();
    event.fields.erase(edr::field::kKerberoastScore);
    engine.OnEvent(event);
    KR_CHECK(!Has(hits, "EDR-254"));
}

} // namespace

void RunKerberoastDetectorTests() {
    TestInspectsDisabledAndEligibility();
    TestDistinctServicesAndThreshold();
    TestRequesterIsolationExpiryAndBounds();
    TestOrderingCooldownEscalationAndNormalization();
    TestRealisticParserIntegrationAndBounds();
    TestConfigStrictAtomic();
    TestProductionRule();
}
