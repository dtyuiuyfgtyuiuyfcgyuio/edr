/*
 * threat_intel_detector_tests.cpp - Unit tests for ThreatIntelDetector.
 *
 * The feed is written to a temp file so the loader path (parse + validate +
 * index) is exercised, not just the matcher. Every test states its own
 * ts100ns so window/expiry behaviour is reproducible.
 */
#include "threat_intel_detector_tests.h"

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "edr_event.h"
#include "event_bus.h"
#include "config.h"
#include "threat_intel_detector.h"
#include "rule_engine.h"

namespace {

#define TI_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond) {
        throw std::runtime_error(
            "threat intel detector test failed at line " +
            std::to_string(line) + ": " + expr);
    }
}

constexpr uint64_t kSecond = 10000000ULL;

/* Feed contents used across the suite. Two hashes, a parent domain and an
 * address so each matching surface is covered. */
const char* const kFeed = R"({
  "feed": "unit-test-feed",
  "indicators": [
    {"id":"TI-1","type":"sha256",
     "value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "confidence":"high","source":"unit","threat":"FamA"},
    {"id":"TI-2","type":"sha256",
     "value":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
     "confidence":"medium","source":"unit-two"},
    {"id":"TI-3","type":"domain","value":"c2.example.test",
     "confidence":"high","source":"unit"},
    {"id":"TI-4","type":"ipv4","value":"203.0.113.77",
     "confidence":"medium","source":"unit"}
  ]
})";

struct FeedFileCleanup {
    std::vector<std::string> paths;
    std::string directory;

    FeedFileCleanup() {
        char root[MAX_PATH] = {};
        const DWORD length = GetTempPathA(MAX_PATH, root);
        if (length == 0 || length >= MAX_PATH)
            throw std::runtime_error("cannot get temporary directory for test feeds");
        const std::string prefix = std::string(root) + "edr-intel-tests-" +
            std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()) + "-";
        for (unsigned attempt = 0; attempt < 128; ++attempt) {
            directory = prefix + std::to_string(attempt);
            if (CreateDirectoryA(directory.c_str(), nullptr)) return;
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                throw std::runtime_error("cannot create private test feed directory");
        }
        throw std::runtime_error("cannot allocate private test feed directory");
    }

    ~FeedFileCleanup() {
        for (const std::string& path : paths) DeleteFileA(path.c_str());
        RemoveDirectoryA(directory.c_str());
    }
};

FeedFileCleanup& FeedFiles() {
    static FeedFileCleanup files;
    return files;
}

std::string WriteFeed(const std::string& body) {
    // Missing-feed tests intentionally release filenames. Separate process
    // directories prevent another concurrently running suite from acquiring
    // those names and later deleting/replacing a live fixture during cleanup.
    const std::string& dir = FeedFiles().directory;
    char pathBuffer[MAX_PATH] = {};
    if (GetTempFileNameA(dir.c_str(), "edr", 0, pathBuffer) == 0)
        throw std::runtime_error("cannot create unique temporary test feed");
    const std::string path(pathBuffer);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        DeleteFileA(path.c_str());
        throw std::runtime_error("cannot write temporary test feed");
    }
    out << body;
    out.close();
    if (!out) {
        DeleteFileA(path.c_str());
        throw std::runtime_error("cannot finish temporary test feed");
    }
    FeedFiles().paths.push_back(path);
    if (std::getenv("EDR_TEST_FEED_TRACE"))
        std::fprintf(stderr, "[feed-trace] pid=%lu write=%s bytes=%zu\n",
            GetCurrentProcessId(), path.c_str(), body.size());
    return path;
}

edr::Event ProcessStart(const std::string& image, const std::string& command,
                        const std::string& sha256, uint32_t pid,
                        uint64_t ts100ns) {
    edr::Event ev;
    ev.type = EDR_EVT_PROCESS_START;
    ev.pid = pid;
    ev.ts100ns = ts100ns;
    ev.processIdentity = "pid:" + std::to_string(pid);
    ev.fields[edr::field::kType] = "PROCESS_START";
    ev.fields[edr::field::kImage] = image;
    ev.fields[edr::field::kCommandLine] = command;
    if (!sha256.empty()) ev.fields[edr::field::kSha256] = sha256;
    return ev;
}

edr::Event DnsQuery(const std::string& name, uint32_t pid, uint64_t ts100ns) {
    edr::Event ev;
    ev.type = EDR_EVT_DNS_QUERY;
    ev.pid = pid;
    ev.ts100ns = ts100ns;
    ev.fields[edr::field::kType] = "DNS_QUERY";
    ev.fields[edr::field::kDnsQueryName] = name;
    return ev;
}

edr::Event NetConnect(const std::string& ip, uint32_t pid, uint64_t ts100ns) {
    edr::Event ev;
    ev.type = EDR_EVT_NET_CONNECT;
    ev.pid = pid;
    ev.ts100ns = ts100ns;
    ev.fields[edr::field::kType] = "NET_CONNECT";
    ev.fields[edr::field::kDstIp] = ip;
    return ev;
}

edr::Event ImageLoad(const std::string& image, const std::string& checksum,
                     uint32_t pid, uint64_t ts100ns) {
    edr::Event ev;
    ev.type = EDR_EVT_IMAGE_LOAD;
    ev.pid = pid;
    ev.ts100ns = ts100ns;
    ev.fields[edr::field::kType] = "IMAGE_LOAD";
    ev.fields[edr::field::kImageLoaded] = image;
    if (!checksum.empty()) ev.fields[edr::field::kImageChecksum] = checksum;
    return ev;
}

void SetReliableProcessIdentity(edr::Event& ev, uint64_t startTime100ns,
                                const std::string& endpoint,
                                const std::string& source) {
    ev.processStartTime100ns = startTime100ns;
    ev.source = source;
    ev.fields[edr::field::kEndpointId] = endpoint;
}

void SetOpaqueProcessIdentity(edr::Event& ev, const std::string& identity,
                              const std::string& endpoint,
                              const std::string& source,
                              bool useSourceField = false) {
    ev.processIdentity = identity;
    ev.fields[edr::field::kEndpointId] = endpoint;
    if (useSourceField)
        ev.fields[edr::field::kSource] = source;
    else
        ev.source = source;
}

std::string SingleIndicatorFeed(const std::string& type,
                                const std::string& value,
                                const std::string& id = "TI-IPv6") {
    std::string feed = "{\"indicators\":[{\"id\":\"";
    feed += id;
    feed += "\",\"type\":\"";
    feed += type;
    feed += "\",\"value\":\"";
    feed += value;
    feed += "\",\"confidence\":\"high\",\"source\":\"unit\"}]}";
    return feed;
}

std::string Field(const edr::Event& ev, const char* name) {
    auto found = ev.fields.find(name);
    return found == ev.fields.end() ? std::string() : found->second;
}

/* Build a detector already loaded with kFeed. Throws if the feed fails to
 * load, so every test starts from a known-good catalog. */
edr::ThreatIntelDetector Loaded(uint32_t minScore = 55,
                                uint32_t dedupSeconds = 300,
                                size_t capacity = 1024) {
    edr::ThreatIntelDetector detector(true, minScore, dedupSeconds, capacity);
    std::string error;
    const std::string path = WriteFeed(kFeed);
    if (!detector.LoadIndicators(path, error))
        throw std::runtime_error("feed load failed: " + error);
    return detector;
}

/* A 64-hex sha256 hit yields the sha256 base score (85) -> MALICIOUS. */
void TestSha256HashMatch() {
    std::fprintf(stderr, "[threat_intel] TestSha256HashMatch\n");
    edr::ThreatIntelDetector detector = Loaded();
    edr::Event ev = ProcessStart(
        "C:\\Users\\x\\AppData\\Local\\Temp\\dropper.exe", "dropper.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        1001, 100 * kSecond);
    detector.Enrich(ev);
    TI_CHECK(Field(ev, edr::field::kThreatIntelScore) == "85");
    TI_CHECK(Field(ev, edr::field::kThreatIntelVerdict) == "MALICIOUS");
    TI_CHECK(Field(ev, edr::field::kThreatIntelIocIds) == "TI-1");
    TI_CHECK(Field(ev, edr::field::kThreatIntelIocTypes) == "sha256");
    TI_CHECK(Field(ev, edr::field::kThreatIntelIocSources) == "unit");
    TI_CHECK(Field(ev, edr::field::kThreatIntelIocConfidence) == "high");
    TI_CHECK(Field(ev, edr::field::kThreatIntelFeed) == "unit-test-feed");
}

/* A hash carried only in the Sysmon `hashes` list must still match. */
void TestHashesListMatch() {
    std::fprintf(stderr, "[threat_intel] TestHashesListMatch\n");
    edr::ThreatIntelDetector detector = Loaded();
    edr::Event ev = ProcessStart(
        "C:\\Users\\x\\AppData\\Local\\Temp\\dropper.exe", "dropper.exe",
        std::string(), 1002, 100 * kSecond);
    ev.fields[edr::field::kHashes] =
        "MD5=00112233445566778899aabbccddeeff,"
        "SHA256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    detector.Enrich(ev);
    TI_CHECK(Field(ev, edr::field::kThreatIntelScore) == "85");
    TI_CHECK(Field(ev, edr::field::kThreatIntelIocIds) == "TI-1");
}

/* An IMAGE_LOAD matching by checksum scores the same as a process hash. */
void TestImageChecksumMatch() {
    std::fprintf(stderr, "[threat_intel] TestImageChecksumMatch\n");
    edr::ThreatIntelDetector detector = Loaded();
    edr::Event ev = ImageLoad(
        "C:\\Windows\\Temp\\evil.dll",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        1003, 100 * kSecond);
    detector.Enrich(ev);
    TI_CHECK(Field(ev, edr::field::kThreatIntelScore) == "85");
    TI_CHECK(Field(ev, edr::field::kThreatIntelIocIds) == "TI-2");
}

/* Exact domain hit scores 60 (SUSPICIOUS band). */
void TestDomainExactMatch() {
    std::fprintf(stderr, "[threat_intel] TestDomainExactMatch\n");
    edr::ThreatIntelDetector detector = Loaded();
    edr::Event ev = DnsQuery("c2.example.test", 1004, 100 * kSecond);
    detector.Enrich(ev);
    TI_CHECK(Field(ev, edr::field::kThreatIntelScore) == "60");
    TI_CHECK(Field(ev, edr::field::kThreatIntelVerdict) == "SUSPICIOUS");
    TI_CHECK(Field(ev, edr::field::kThreatIntelIocTypes) == "domain");
}

/* A subdomain of an indicator matches, and the trailing DNS root dot is
 * ignored. Uppercase input must normalize. */
void TestDomainSubdomainAndCaseMatch() {
    std::fprintf(stderr, "[threat_intel] TestDomainSubdomainAndCaseMatch\n");
    edr::ThreatIntelDetector detector = Loaded();
    edr::Event ev = DnsQuery("Beacon.C2.Example.Test.", 1005, 100 * kSecond);
    detector.Enrich(ev);
    TI_CHECK(Field(ev, edr::field::kThreatIntelScore) == "60");
    TI_CHECK(Field(ev, edr::field::kThreatIntelIocIds) == "TI-3");
}

/* A suffix that is not on a label boundary must NOT match: this is the
 * classic `notexample.com` vs `example.com` false positive. */
void TestDomainBoundaryNotMatched() {
    std::fprintf(stderr, "[threat_intel] TestDomainBoundaryNotMatched\n");
    edr::ThreatIntelDetector detector = Loaded();
    edr::Event ev = DnsQuery("evilc2.example.test.attacker.net", 1006,
                             100 * kSecond);
    detector.Enrich(ev);
    TI_CHECK(Field(ev, edr::field::kThreatIntelScore).empty());
    TI_CHECK(ev.fields.count(edr::field::kThreatIntelVerdict) == 0);
}

/* Address indicator matches NET_CONNECT dst_ip. */
void TestAddressMatch() {
    std::fprintf(stderr, "[threat_intel] TestAddressMatch\n");
    edr::ThreatIntelDetector detector = Loaded();
    edr::Event ev = NetConnect("203.0.113.77", 1007, 100 * kSecond);
    detector.Enrich(ev);
    TI_CHECK(Field(ev, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(ev, edr::field::kThreatIntelIocTypes) == "ipv4");
}

/* Two hits of different types on the same process add the cross-type bonus:
 * 85 (hash peak) + 15 = 100, and both ids/types are reported. */
void TestCrossTypeBonus() {
    std::fprintf(stderr, "[threat_intel] TestCrossTypeBonus\n");
    edr::ThreatIntelDetector detector = Loaded();
    const uint32_t pid = 1008;
    edr::Event first = ProcessStart(
        "C:\\Users\\x\\AppData\\Local\\Temp\\dropper.exe", "dropper.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pid, 100 * kSecond);
    SetReliableProcessIdentity(first, 8001, "endpoint-A", "Sysmon");
    detector.Enrich(first);
    TI_CHECK(Field(first, edr::field::kThreatIntelScore) == "85");

    edr::Event second = NetConnect("203.0.113.77", pid, 101 * kSecond);
    SetReliableProcessIdentity(second, 8001, "endpoint-A", "ETW");
    detector.Enrich(second);
    TI_CHECK(Field(second, edr::field::kThreatIntelScore) == "100");
    TI_CHECK(Field(second, edr::field::kThreatIntelVerdict) == "MALICIOUS");
    TI_CHECK(Field(second, edr::field::kThreatIntelIocIds) == "TI-1,TI-4");
    TI_CHECK(Field(second, edr::field::kThreatIntelIocTypes) == "sha256,ipv4");
    TI_CHECK(Field(second, edr::field::kThreatIntelIocCount) == "2");
}

/* min_score suppresses both the score and the verdict; a partial annotation
 * would be misleading to a rule matching the verdict field. */
void TestMinScoreSuppressesAnnotation() {
    std::fprintf(stderr, "[threat_intel] TestMinScoreSuppressesAnnotation\n");
    /* min_score 70 is above the domain base score of 60. */
    edr::ThreatIntelDetector detector = Loaded(70);
    edr::Event ev = DnsQuery("c2.example.test", 1009, 100 * kSecond);
    detector.Enrich(ev);
    TI_CHECK(Field(ev, edr::field::kThreatIntelScore).empty());
    TI_CHECK(ev.fields.count(edr::field::kThreatIntelVerdict) == 0);
}

/* A hash below the min_score is silent, but raising the priority of the same
 * process with a second, stronger type still crosses the bar. */
void TestMinScoreBoundary() {
    std::fprintf(stderr, "[threat_intel] TestMinScoreBoundary\n");
    edr::ThreatIntelDetector detector = Loaded(75);
    edr::Event weak = DnsQuery("c2.example.test", 1010, 100 * kSecond);
    detector.Enrich(weak);
    TI_CHECK(Field(weak, edr::field::kThreatIntelScore).empty());

    edr::Event strong = ProcessStart(
        "C:\\Users\\x\\nomatch.exe", "nomatch.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        1011, 100 * kSecond);
    detector.Enrich(strong);
    TI_CHECK(Field(strong, edr::field::kThreatIntelScore) == "85");
    TI_CHECK(Field(strong, edr::field::kThreatIntelVerdict) == "MALICIOUS");
}

/* Non-indexed event types are not inspected at all. */
void TestUnrelatedEventIgnored() {
    std::fprintf(stderr, "[threat_intel] TestUnrelatedEventIgnored\n");
    TI_CHECK(!edr::ThreatIntelDetector::Inspects(EDR_EVT_REG_WRITE));
    TI_CHECK(!edr::ThreatIntelDetector::Inspects(EDR_EVT_FILE_CREATE));
    TI_CHECK(edr::ThreatIntelDetector::Inspects(EDR_EVT_PROCESS_START));
    TI_CHECK(edr::ThreatIntelDetector::Inspects(EDR_EVT_DNS_QUERY));
    TI_CHECK(edr::ThreatIntelDetector::Inspects(EDR_EVT_NET_CONNECT));
    TI_CHECK(edr::ThreatIntelDetector::Inspects(EDR_EVT_IMAGE_LOAD));

    edr::ThreatIntelDetector detector = Loaded();
    edr::Event ev;
    ev.type = EDR_EVT_REG_WRITE;
    ev.pid = 1012;
    ev.ts100ns = 100 * kSecond;
    ev.fields[edr::field::kRegKey] = "HKLM\\Software\\Test";
    detector.Enrich(ev);
    TI_CHECK(ev.fields.count(edr::field::kThreatIntelScore) == 0);
}

/* A malformed feed must fail the load loudly and leave no partial index:
 * detecting on half a feed would silently under-report. */
void TestMalformedFeedRejected() {
    std::fprintf(stderr, "[threat_intel] TestMalformedFeedRejected\n");
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    std::string error;
    const std::string path = WriteFeed(
        R"({"indicators":[{"id":"TI-9","type":"sha256","value":"nothex",
        "confidence":"high","source":"unit"}]})");
    TI_CHECK(!detector.LoadIndicators(path, error));
    TI_CHECK(!error.empty());
    TI_CHECK(detector.IndicatorCount() == 0);

    /* With no indicators loaded nothing may be annotated. */
    edr::Event ev = ProcessStart(
        "C:\\Users\\x\\AppData\\Local\\Temp\\dropper.exe", "dropper.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        1013, 100 * kSecond);
    detector.Enrich(ev);
    TI_CHECK(ev.fields.count(edr::field::kThreatIntelScore) == 0);
}

/* Unknown indicator fields are rejected so a typo cannot silently disable a
 * whole feed. */
void TestUnknownIndicatorFieldRejected() {
    std::fprintf(stderr, "[threat_intel] TestUnknownIndicatorFieldRejected\n");
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    std::string error;
    const std::string path = WriteFeed(
        R"({"indicators":[{"id":"TI-9","type":"ipv4","value":"203.0.113.9",
        "confidence":"high","source":"unit","severity":"high"}]})");
    TI_CHECK(!detector.LoadIndicators(path, error));
    TI_CHECK(detector.IndicatorCount() == 0);
}

/* Missing file is an error, not an empty catalog. */
void TestMissingFeedRejected() {
    std::fprintf(stderr, "[threat_intel] TestMissingFeedRejected\n");
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    std::string error;
    TI_CHECK(!detector.LoadIndicators("Z:\\no\\such\\feed.json", error));
    TI_CHECK(error.find("cannot open") != std::string::npos);
}

/* Bounded state: a long tail of distinct processes must not grow without
 * limit under the configured capacity. */
void TestStateCapacityBounded() {
    std::fprintf(stderr, "[threat_intel] TestStateCapacityBounded\n");
    edr::ThreatIntelDetector detector = Loaded(55, 300, 4);
    for (uint32_t i = 0; i < 64; ++i) {
        edr::Event ev = DnsQuery("c2.example.test", 2000 + i,
                                 (100 + i) * kSecond);
        SetReliableProcessIdentity(ev, 10000 + i, "endpoint-capacity", "Sysmon");
        detector.Enrich(ev);
    }
    TI_CHECK(detector.StateCount() == 4);
}

/* State expires after the dedup window, so a later hit is evaluated afresh
 * rather than being suppressed by stale state. */
void TestStateExpiry() {
    std::fprintf(stderr, "[threat_intel] TestStateExpiry\n");
    edr::ThreatIntelDetector detector = Loaded(55, 60, 1024);
    edr::Event first = ProcessStart(
        "C:\\Users\\x\\AppData\\Local\\Temp\\dropper.exe", "dropper.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        3001, 100 * kSecond);
    SetReliableProcessIdentity(first, 8301, "endpoint-A", "Sysmon");
    detector.Enrich(first);
    TI_CHECK(Field(first, edr::field::kThreatIntelScore) == "85");

    /* Well past the 60s window: the process state is gone, so a lone address
     * hit scores its own base value with no cross-type bonus. */
    edr::Event later = NetConnect("203.0.113.77", 3001, 500 * kSecond);
    SetReliableProcessIdentity(later, 8301, "endpoint-A", "ETW");
    detector.Enrich(later);
    TI_CHECK(Field(later, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(later, edr::field::kThreatIntelIocTypes) == "ipv4");
}

/* A disabled detector never annotates, even with a loaded feed. */
void TestDisabledDetectorInert() {
    std::fprintf(stderr, "[threat_intel] TestDisabledDetectorInert\n");
    edr::ThreatIntelDetector detector(false, 55, 300, 1024);
    std::string error;
    const std::string path = WriteFeed(kFeed);
    TI_CHECK(detector.LoadIndicators(path, error));
    TI_CHECK(detector.IndicatorCount() == 4);
    edr::Event ev = ProcessStart(
        "C:\\Users\\x\\AppData\\Local\\Temp\\dropper.exe", "dropper.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        4001, 100 * kSecond);
    detector.Enrich(ev);
    TI_CHECK(ev.fields.count(edr::field::kThreatIntelScore) == 0);
}

/* Top-level array form (no wrapper object) must load. */
void TestBareArrayFeed() {
    std::fprintf(stderr, "[threat_intel] TestBareArrayFeed\n");
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    std::string error;
    const std::string path = WriteFeed(
        R"([{"id":"TI-A","type":"ipv6","value":"2001:db8::1",
        "confidence":"low","source":"unit"}])");
    TI_CHECK(detector.LoadIndicators(path, error));
    TI_CHECK(detector.IndicatorCount() == 1);

    edr::Event ev = NetConnect("2001:db8::1", 5001, 100 * kSecond);
    detector.Enrich(ev);
    TI_CHECK(Field(ev, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(ev, edr::field::kThreatIntelIocTypes) == "ipv6");
}

/* Equivalent IPv6 spellings in a feed and an event denote the same address.
 * Both directions are exercised through the actual feed loader and matcher. */
void TestIpv6EquivalentSpellingsMatch() {
    std::fprintf(stderr, "[threat_intel] TestIpv6EquivalentSpellingsMatch\n");
    const std::string expanded = "2001:0DB8:0000:0000:0000:0000:0000:0001";
    const std::string compressed = "2001:db8::1";

    edr::ThreatIntelDetector expandedFeed(true, 55, 300, 1024);
    std::string error;
    TI_CHECK(expandedFeed.LoadIndicators(
        WriteFeed(
                  SingleIndicatorFeed("ipv6", expanded)), error));
    edr::Event compressedEvent = NetConnect(compressed, 5101, 100 * kSecond);
    expandedFeed.Enrich(compressedEvent);
    TI_CHECK(Field(compressedEvent, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(compressedEvent, edr::field::kThreatIntelIocIds) == "TI-IPv6");
    TI_CHECK(Field(compressedEvent, edr::field::kThreatIntelIocTypes) == "ipv6");
    edr::Event differentAddress = NetConnect("2001:db8::2", 5104,
                                              100 * kSecond);
    expandedFeed.Enrich(differentAddress);
    TI_CHECK(Field(differentAddress, edr::field::kThreatIntelScore).empty());
    TI_CHECK(differentAddress.fields.count(edr::field::kThreatIntelVerdict) == 0);

    edr::ThreatIntelDetector compressedFeed(true, 55, 300, 1024);
    error.clear();
    TI_CHECK(compressedFeed.LoadIndicators(
        WriteFeed(
                  SingleIndicatorFeed("ipv6", compressed)), error));
    edr::Event expandedEvent = NetConnect(expanded, 5102, 100 * kSecond);
    compressedFeed.Enrich(expandedEvent);
    TI_CHECK(Field(expandedEvent, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(expandedEvent, edr::field::kThreatIntelIocTypes) == "ipv6");
}

/* IPv4-mapped IPv6 stays in the IPv6 indicator namespace, even when the feed
 * also contains the corresponding IPv4 address. */
void TestIpv4MappedIpv6RemainsIpv6() {
    std::fprintf(stderr, "[threat_intel] TestIpv4MappedIpv6RemainsIpv6\n");
    const std::string feed = R"({"indicators":[
      {"id":"TI-MAPPED","type":"ipv6","value":"::ffff:192.0.2.1",
       "confidence":"high","source":"unit"},
      {"id":"TI-IPV4","type":"ipv4","value":"192.0.2.1",
       "confidence":"high","source":"unit"}]})";
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    std::string error;
    TI_CHECK(detector.LoadIndicators(
        WriteFeed(feed), error));

    edr::Event ev = NetConnect("0:0:0:0:0:ffff:c000:0201", 5103,
                               100 * kSecond);
    detector.Enrich(ev);
    TI_CHECK(Field(ev, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(ev, edr::field::kThreatIntelIocIds) == "TI-MAPPED");
    TI_CHECK(Field(ev, edr::field::kThreatIntelIocTypes) == "ipv6");
}

/* Duplicate IPv6 indicators are rejected after address normalization, so
 * equivalent textual forms cannot create duplicate feed entries. */
void TestIpv6EquivalentIndicatorsRejectedAsDuplicate() {
    std::fprintf(stderr,
                 "[threat_intel] TestIpv6EquivalentIndicatorsRejectedAsDuplicate\n");
    const std::string feed = R"({"indicators":[
      {"id":"TI-COMPRESSED","type":"ipv6","value":"2001:db8::1",
       "confidence":"high","source":"unit"},
      {"id":"TI-EXPANDED","type":"ipv6",
       "value":"2001:0db8:0:0:0:0:0:1",
       "confidence":"high","source":"unit"}]})";
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    std::string error;
    TI_CHECK(!detector.LoadIndicators(
        WriteFeed(feed), error));
    TI_CHECK(!error.empty());
    TI_CHECK(detector.IndicatorCount() == 0);
}

/* Invalid compression, multiple compression markers, and embedded NUL must
 * fail the whole feed instead of entering the address index. */
void TestMalformedIpv6IndicatorsRejected() {
    std::fprintf(stderr, "[threat_intel] TestMalformedIpv6IndicatorsRejected\n");
    const char* const invalidValues[] = {
        "1:2:3:4:5:6:7:8::",
        "2001::db8::1",
        "2001:db8::1\\u0000",
    };
    for (size_t i = 0; i < sizeof(invalidValues) / sizeof(invalidValues[0]); ++i) {
        edr::ThreatIntelDetector detector(true, 55, 300, 1024);
        std::string error;
        const std::string body = SingleIndicatorFeed("ipv6", invalidValues[i]);
        TI_CHECK(!detector.LoadIndicators(
            WriteFeed(body), error));
        TI_CHECK(!error.empty());
        TI_CHECK(detector.IndicatorCount() == 0);
    }
}

void TestIpv6EventWithEmbeddedNulDoesNotMatchValidPrefix() {
    std::fprintf(stderr,
                 "[threat_intel] TestIpv6EventWithEmbeddedNulDoesNotMatchValidPrefix\n");
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    std::string error;
    TI_CHECK(detector.LoadIndicators(
        WriteFeed(
                  SingleIndicatorFeed("ipv6", "2001:db8::1")), error));

    std::string invalidAddress = "2001:db8::1";
    invalidAddress.push_back('\0');
    invalidAddress += "ignored";
    edr::Event ev = NetConnect(invalidAddress, 5105, 100 * kSecond);
    detector.Enrich(ev);
    TI_CHECK(Field(ev, edr::field::kThreatIntelScore).empty());
    TI_CHECK(ev.fields.count(edr::field::kThreatIntelVerdict) == 0);
}

/* Exact process creation time is provider-neutral, while endpoint identity
 * remains part of the key. */
void TestReliableProcessIdentityAccumulatesAcrossProviders() {
    std::fprintf(stderr,
                 "[threat_intel] TestReliableProcessIdentityAccumulatesAcrossProviders\n");
    edr::ThreatIntelDetector detector = Loaded();
    const uint32_t pid = 5201;
    edr::Event start = ProcessStart("dropper.exe", "dropper.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pid, 100 * kSecond);
    SetReliableProcessIdentity(start, 9001, "endpoint-A", "Sysmon");
    detector.Enrich(start);
    TI_CHECK(Field(start, edr::field::kThreatIntelScore) == "85");

    edr::Event connect = NetConnect("203.0.113.77", pid, 101 * kSecond);
    SetReliableProcessIdentity(connect, 9001, "endpoint-A", "ETW");
    detector.Enrich(connect);
    TI_CHECK(Field(connect, edr::field::kThreatIntelScore) == "100");
    TI_CHECK(Field(connect, edr::field::kThreatIntelIocIds) == "TI-1,TI-4");
}

void TestDifferentProcessInstanceDoesNotInheritIocs() {
    std::fprintf(stderr,
                 "[threat_intel] TestDifferentProcessInstanceDoesNotInheritIocs\n");
    edr::ThreatIntelDetector detector = Loaded();
    const uint32_t pid = 5202;
    edr::Event oldInstance = ProcessStart("dropper.exe", "dropper.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pid, 100 * kSecond);
    SetReliableProcessIdentity(oldInstance, 9101, "endpoint-A", "Sysmon");
    detector.Enrich(oldInstance);
    TI_CHECK(Field(oldInstance, edr::field::kThreatIntelScore) == "85");

    /* A new PROCESS_START without an IOC need not eagerly replace state. */
    edr::Event newStart = ProcessStart("clean.exe", "clean.exe", "", pid,
                                       101 * kSecond);
    SetReliableProcessIdentity(newStart, 9102, "endpoint-A", "ETW");
    detector.Enrich(newStart);
    TI_CHECK(Field(newStart, edr::field::kThreatIntelScore).empty());

    edr::Event connect = NetConnect("203.0.113.77", pid, 102 * kSecond);
    SetReliableProcessIdentity(connect, 9102, "endpoint-A", "Sysmon");
    detector.Enrich(connect);
    TI_CHECK(Field(connect, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(connect, edr::field::kThreatIntelIocIds) == "TI-4");
    TI_CHECK(Field(connect, edr::field::kThreatIntelIocTypes) == "ipv4");
}

void TestSameExactIdentityDoesNotIncreaseStateCount() {
    std::fprintf(stderr,
                 "[threat_intel] TestSameExactIdentityDoesNotIncreaseStateCount\n");
    edr::ThreatIntelDetector detector = Loaded();
    const uint32_t pid = 5210;
    for (uint64_t i = 0; i < 32; ++i) {
        edr::Event connect = NetConnect("203.0.113.77", pid,
                                        (100 + i) * kSecond);
        SetReliableProcessIdentity(connect, 9401, "endpoint-A",
                                   i == 0 ? "Sysmon" : "ETW");
        detector.Enrich(connect);
        TI_CHECK(Field(connect, edr::field::kThreatIntelScore) == "65");
        TI_CHECK(detector.StateCount() == 1);
    }
}

void TestNewExactIdentityReclaimsOldState() {
    std::fprintf(stderr,
                 "[threat_intel] TestNewExactIdentityReclaimsOldState\n");
    edr::ThreatIntelDetector detector = Loaded();
    const uint32_t pid = 5211;
    edr::Event oldInstance = ProcessStart("dropper.exe", "dropper.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pid, 100 * kSecond);
    SetReliableProcessIdentity(oldInstance, 9501, "endpoint-A", "Sysmon");
    detector.Enrich(oldInstance);
    TI_CHECK(detector.StateCount() == 1);

    edr::Event newInstance = NetConnect("203.0.113.77", pid, 101 * kSecond);
    SetReliableProcessIdentity(newInstance, 9502, "endpoint-A", "ETW");
    detector.Enrich(newInstance);
    TI_CHECK(Field(newInstance, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(newInstance, edr::field::kThreatIntelIocIds) == "TI-4");
    TI_CHECK(detector.StateCount() == 1);
}

void TestDifferentEndpointDoesNotInheritIocs() {
    std::fprintf(stderr,
                 "[threat_intel] TestDifferentEndpointDoesNotInheritIocs\n");
    edr::ThreatIntelDetector detector = Loaded();
    const uint32_t pid = 5203;
    edr::Event start = ProcessStart("dropper.exe", "dropper.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pid, 100 * kSecond);
    SetReliableProcessIdentity(start, 9201, "endpoint-A", "Sysmon");
    detector.Enrich(start);

    edr::Event connect = NetConnect("203.0.113.77", pid, 101 * kSecond);
    SetReliableProcessIdentity(connect, 9201, "endpoint-B", "ETW");
    detector.Enrich(connect);
    TI_CHECK(Field(connect, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(connect, edr::field::kThreatIntelIocIds) == "TI-4");
}

void TestOpaqueIdentityIsScopedToSource() {
    std::fprintf(stderr,
                 "[threat_intel] TestOpaqueIdentityIsScopedToSource\n");
    edr::ThreatIntelDetector sameSource = Loaded();
    const uint32_t samePid = 5204;
    edr::Event start = ProcessStart("dropper.exe", "dropper.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        samePid, 100 * kSecond);
    SetOpaqueProcessIdentity(start, "sequence@77", "endpoint-A", "ETW", true);
    sameSource.Enrich(start);
    edr::Event sameSourceConnect = NetConnect("203.0.113.77", samePid,
                                               101 * kSecond);
    SetOpaqueProcessIdentity(sameSourceConnect, "sequence@77", "endpoint-A",
                             "etw", true);
    sameSource.Enrich(sameSourceConnect);
    TI_CHECK(Field(sameSourceConnect, edr::field::kThreatIntelScore) == "100");

    edr::ThreatIntelDetector differentSource = Loaded();
    const uint32_t otherPid = 5205;
    edr::Event otherStart = ProcessStart("dropper.exe", "dropper.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        otherPid, 100 * kSecond);
    SetOpaqueProcessIdentity(otherStart, "sequence@77", "endpoint-A", "Sysmon");
    differentSource.Enrich(otherStart);
    edr::Event otherConnect = NetConnect("203.0.113.77", otherPid,
                                         101 * kSecond);
    SetOpaqueProcessIdentity(otherConnect, "sequence@77", "endpoint-A", "ETW");
    differentSource.Enrich(otherConnect);
    TI_CHECK(Field(otherConnect, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(otherConnect, edr::field::kThreatIntelIocIds) == "TI-4");

    edr::ThreatIntelDetector differentEndpoint = Loaded();
    edr::Event endpointStart = ProcessStart("dropper.exe", "dropper.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        5207, 100 * kSecond);
    SetOpaqueProcessIdentity(endpointStart, "sequence@88", "endpoint-A", "ETW");
    differentEndpoint.Enrich(endpointStart);
    edr::Event endpointConnect = NetConnect("203.0.113.77", 5207,
                                             101 * kSecond);
    SetOpaqueProcessIdentity(endpointConnect, "sequence@88", "endpoint-B", "ETW");
    differentEndpoint.Enrich(endpointConnect);
    TI_CHECK(Field(endpointConnect, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(endpointConnect, edr::field::kThreatIntelIocIds) == "TI-4");
}

void TestUnreliableIdentityIsEventLocalAndCannotPolluteState() {
    std::fprintf(stderr,
                 "[threat_intel] TestUnreliableIdentityIsEventLocalAndCannotPolluteState\n");
    edr::ThreatIntelDetector detector = Loaded();
    const uint32_t pid = 5206;
    edr::Event reliableStart = ProcessStart("dropper.exe", "dropper.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pid, 100 * kSecond);
    SetReliableProcessIdentity(reliableStart, 9301, "endpoint-A", "Sysmon");
    detector.Enrich(reliableStart);
    TI_CHECK(Field(reliableStart, edr::field::kThreatIntelScore) == "85");

    /* The helper supplies only a bare PID identity. This event is scored by
     * itself but must not change the reliable process's stored evidence. */
    edr::Event unidentified = NetConnect("203.0.113.77", pid, 101 * kSecond);
    unidentified.processStartTime100ns = 0;
    unidentified.processIdentity.clear();
    detector.Enrich(unidentified);
    TI_CHECK(Field(unidentified, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(unidentified, edr::field::kThreatIntelIocIds) == "TI-4");
    TI_CHECK(detector.StateCount() == 1);

    edr::Event barePid = NetConnect("203.0.113.77", pid, 101 * kSecond);
    TI_CHECK(barePid.processStartTime100ns == 0);
    detector.Enrich(barePid);
    TI_CHECK(Field(barePid, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(barePid, edr::field::kThreatIntelIocIds) == "TI-4");
    TI_CHECK(detector.StateCount() == 1);

    edr::Event reliableConnect = NetConnect("203.0.113.77", pid,
                                              102 * kSecond);
    SetReliableProcessIdentity(reliableConnect, 9301, "endpoint-A", "ETW");
    detector.Enrich(reliableConnect);
    TI_CHECK(Field(reliableConnect, edr::field::kThreatIntelScore) == "100");
    TI_CHECK(Field(reliableConnect, edr::field::kThreatIntelIocIds) == "TI-1,TI-4");
}

void TestOpaqueIdentityWithoutSourceIsEventLocal() {
    std::fprintf(stderr,
                 "[threat_intel] TestOpaqueIdentityWithoutSourceIsEventLocal\n");
    edr::ThreatIntelDetector detector = Loaded();
    const uint32_t pid = 5208;
    edr::Event start = ProcessStart("dropper.exe", "dropper.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pid, 100 * kSecond);
    SetOpaqueProcessIdentity(start, "sequence@90", "endpoint-A", "");
    detector.Enrich(start);
    TI_CHECK(Field(start, edr::field::kThreatIntelScore) == "85");
    TI_CHECK(detector.StateCount() == 0);

    edr::Event connect = NetConnect("203.0.113.77", pid, 101 * kSecond);
    SetOpaqueProcessIdentity(connect, "sequence@90", "endpoint-A", "");
    detector.Enrich(connect);
    TI_CHECK(Field(connect, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(connect, edr::field::kThreatIntelIocIds) == "TI-4");
    TI_CHECK(detector.StateCount() == 0);
}

void TestOpaqueIdentityKeyLengthPrefixesPreventDelimiterCollision() {
    std::fprintf(stderr,
        "[threat_intel] TestOpaqueIdentityKeyLengthPrefixesPreventDelimiterCollision\n");
    edr::ThreatIntelDetector detector = Loaded();
    const uint32_t pid = 5212;
    edr::Event first = ProcessStart("dropper.exe", "dropper.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pid, 100 * kSecond);
    SetOpaqueProcessIdentity(first, "c:opaque:d:e", "a:b", "f:g:h");
    detector.Enrich(first);
    TI_CHECK(Field(first, edr::field::kThreatIntelScore) == "85");
    TI_CHECK(detector.StateCount() == 1);

    /* A delimiter-joined representation would make these endpoint, identity,
     * and source components ambiguous. Length prefixes must keep them apart. */
    edr::Event second = NetConnect("203.0.113.77", pid, 101 * kSecond);
    SetOpaqueProcessIdentity(second, "d:e:f", "a:b:opaque:c", "g:h");
    detector.Enrich(second);
    TI_CHECK(Field(second, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(second, edr::field::kThreatIntelIocIds) == "TI-4");
    TI_CHECK(detector.StateCount() == 2);
}

void TestRejectedReplacementPreservesActiveFeed() {
    std::fprintf(stderr, "[threat_intel] TestRejectedReplacementPreservesActiveFeed\n");
    edr::ThreatIntelDetector detector = Loaded();
    std::string error;
    TI_CHECK(!detector.LoadIndicators(WriteFeed(
        R"({"feed":"broken-feed","indicators":[{"id":"bad"}]})"), error));
    TI_CHECK(!error.empty());
    TI_CHECK(detector.IndicatorCount() == 4);
    TI_CHECK(detector.FeedName() == "unit-test-feed");
    TI_CHECK(!detector.ReloadIndicatorsIfChanged(error));
    TI_CHECK(error.empty());
    edr::Event event = DnsQuery("c2.example.test", 6001, 100 * kSecond);
    detector.Enrich(event);
    TI_CHECK(Field(event, edr::field::kThreatIntelScore) == "60");
    TI_CHECK(Field(event, edr::field::kThreatIntelFeed) == "unit-test-feed");
}

void TestSuccessfulReplacementClearsOldEvidence() {
    std::fprintf(stderr, "[threat_intel] TestSuccessfulReplacementClearsOldEvidence\n");
    edr::ThreatIntelDetector detector = Loaded();
    edr::Event old = ProcessStart("dropper.exe", "dropper.exe",
        std::string(64, 'a'), 6002, 100 * kSecond);
    SetReliableProcessIdentity(old, 1234, "endpoint-A", "ETW");
    detector.Enrich(old);
    TI_CHECK(detector.StateCount() == 1);
    std::string error;
    TI_CHECK(detector.LoadIndicators(WriteFeed(SingleIndicatorFeed(
        "ipv4", "203.0.113.77", "TI-new")), error));
    edr::Event current = NetConnect("203.0.113.77", 6002, 101 * kSecond);
    SetReliableProcessIdentity(current, 1234, "endpoint-A", "ETW");
    detector.Enrich(current);
    TI_CHECK(Field(current, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(current, edr::field::kThreatIntelIocIds) == "TI-new");
    TI_CHECK(Field(current, edr::field::kThreatIntelFeed).empty());
}

void ReplaceFeed(const std::string& path, const std::string& contents) {
    if (std::getenv("EDR_TEST_FEED_TRACE"))
        std::fprintf(stderr, "[feed-trace] pid=%lu replace=%s bytes=%zu\n",
            GetCurrentProcessId(), path.c_str(), contents.size());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << contents;
    out.close();
    TI_CHECK(static_cast<bool>(out));
}

void TestConcurrentFeedNamespaceIsolation() {
    std::fprintf(stderr, "[threat_intel] TestConcurrentFeedNamespaceIsolation\n");
    const std::string owned = WriteFeed(kFeed);
    const std::string leaf = owned.substr(owned.find_last_of("\\/") + 1);
    TI_CHECK(DeleteFileA(owned.c_str()) != FALSE);
    {
        FeedFileCleanup sibling;
        const std::string other = sibling.directory + "\\" + leaf;
        ReplaceFeed(other, "{");
        sibling.paths.push_back(other);
        ReplaceFeed(owned, kFeed);
    }
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    std::string error;
    TI_CHECK(detector.LoadIndicators(owned, error));
    TI_CHECK(detector.IndicatorCount() == 4);
}

void TestReloadDetectsSameSizeAndTimestampReplacement() {
    std::fprintf(stderr, "[threat_intel] TestReloadDetectsSameSizeAndTimestampReplacement\n");
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    const std::string path = WriteFeed(SingleIndicatorFeed("domain", "aa.example.test"));
    std::string error;
    TI_CHECK(detector.LoadIndicators(path, error));
    HANDLE file = CreateFileA(path.c_str(), FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    TI_CHECK(file != INVALID_HANDLE_VALUE);
    FILETIME before = {};
    const bool captured = GetFileTime(file, nullptr, nullptr, &before) != FALSE;
    CloseHandle(file);
    TI_CHECK(captured);
    ReplaceFeed(path, SingleIndicatorFeed("domain", "bb.example.test"));
    file = CreateFileA(path.c_str(), FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    TI_CHECK(file != INVALID_HANDLE_VALUE);
    const bool restored = SetFileTime(file, nullptr, nullptr, &before) != FALSE;
    CloseHandle(file);
    TI_CHECK(restored);
    TI_CHECK(detector.ReloadIndicatorsIfChanged(error));
    TI_CHECK(error.empty());
    edr::Event old = DnsQuery("aa.example.test", 6010, 100 * kSecond);
    edr::Event current = DnsQuery("bb.example.test", 6011, 100 * kSecond);
    detector.Enrich(old);
    detector.Enrich(current);
    TI_CHECK(Field(old, edr::field::kThreatIntelScore).empty());
    TI_CHECK(Field(current, edr::field::kThreatIntelScore) == "60");
    TI_CHECK(!detector.ReloadIndicatorsIfChanged(error));
    TI_CHECK(error.empty());
}

void TestUnchangedAndInvalidReloadRetainProcessEvidence() {
    std::fprintf(stderr, "[threat_intel] TestUnchangedAndInvalidReloadRetainProcessEvidence\n");
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    const std::string path = WriteFeed(kFeed);
    std::string error;
    TI_CHECK(detector.LoadIndicators(path, error));
    edr::Event old = ProcessStart("dropper.exe", "dropper.exe",
        std::string(64, 'a'), 6012, 100 * kSecond);
    SetReliableProcessIdentity(old, 2345, "endpoint-A", "ETW");
    detector.Enrich(old);
    TI_CHECK(!detector.ReloadIndicatorsIfChanged(error));
    TI_CHECK(error.empty());
    TI_CHECK(detector.StateCount() == 1);
    ReplaceFeed(path, R"({"feed":"broken","indicators":[{"id":"bad"}]})");
    TI_CHECK(!detector.ReloadIndicatorsIfChanged(error));
    TI_CHECK(!error.empty());
    TI_CHECK(!detector.ReloadIndicatorsIfChanged(error));
    TI_CHECK(!error.empty());
    TI_CHECK(detector.StateCount() == 1);
    TI_CHECK(detector.IndicatorCount() == 4);
    TI_CHECK(detector.FeedName() == "unit-test-feed");
    edr::Event current = NetConnect("203.0.113.77", 6012, 101 * kSecond);
    SetReliableProcessIdentity(current, 2345, "endpoint-A", "ETW");
    detector.Enrich(current);
    TI_CHECK(Field(current, edr::field::kThreatIntelScore) == "100");
    ReplaceFeed(path, SingleIndicatorFeed("ipv4", "203.0.113.77", "TI-new"));
    TI_CHECK(detector.ReloadIndicatorsIfChanged(error));
    TI_CHECK(error.empty());
    TI_CHECK(detector.StateCount() == 0);
    edr::Event updated = NetConnect("203.0.113.77", 6012, 102 * kSecond);
    SetReliableProcessIdentity(updated, 2345, "endpoint-A", "ETW");
    detector.Enrich(updated);
    TI_CHECK(Field(updated, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(updated, edr::field::kThreatIntelIocIds) == "TI-new");
    TI_CHECK(Field(updated, edr::field::kThreatIntelFeed).empty());
}

void TestMissingFeedRecoversWithoutRestart() {
    std::fprintf(stderr, "[threat_intel] TestMissingFeedRecoversWithoutRestart\n");
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    const std::string path = WriteFeed(kFeed);
    TI_CHECK(DeleteFileA(path.c_str()) != FALSE);
    std::string error;
    TI_CHECK(!detector.LoadIndicators(path, error));
    TI_CHECK(!error.empty());
    ReplaceFeed(path, kFeed);
    TI_CHECK(detector.ReloadIndicatorsIfChanged(error));
    TI_CHECK(error.empty());
    TI_CHECK(DeleteFileA(path.c_str()) != FALSE);
    TI_CHECK(!detector.ReloadIndicatorsIfChanged(error));
    TI_CHECK(!error.empty());
    TI_CHECK(detector.IndicatorCount() == 4);
    ReplaceFeed(path, kFeed);
    TI_CHECK(!detector.ReloadIndicatorsIfChanged(error));
    TI_CHECK(error.empty());
}

void TestEmptyAndOversizedReplacementsPreserveFeed() {
    std::fprintf(stderr, "[threat_intel] TestEmptyAndOversizedReplacementsPreserveFeed\n");
    edr::ThreatIntelDetector detector = Loaded();
    std::string error;
    TI_CHECK(!detector.LoadIndicators(WriteFeed("{\"indicators\":[]}"), error));
    TI_CHECK(!error.empty());
    TI_CHECK(detector.IndicatorCount() == 4);
    std::string exact = kFeed;
    exact.resize(4u * 1024u * 1024u, ' ');
    TI_CHECK(detector.LoadIndicators(WriteFeed(exact), error));
    TI_CHECK(!detector.LoadIndicators(WriteFeed(exact + " "), error));
    TI_CHECK(!error.empty());
    TI_CHECK(detector.IndicatorCount() == 4);
    edr::Event event = DnsQuery("c2.example.test", 6013, 100 * kSecond);
    detector.Enrich(event);
    TI_CHECK(Field(event, edr::field::kThreatIntelScore) == "60");
}

void TestAutomaticReloadIsOptInAndRecoversReadErrors() {
    std::fprintf(stderr, "[threat_intel] TestAutomaticReloadIsOptInAndRecoversReadErrors\n");
    edr::ThreatIntelDetector automatic(true, 55, 300, 1024, 1);
    edr::ThreatIntelDetector manual(true, 55, 300, 1024);
    const std::string path = WriteFeed(SingleIndicatorFeed("domain", "aa.example.test"));
    std::string error;
    TI_CHECK(automatic.LoadIndicators(path, error));
    TI_CHECK(manual.LoadIndicators(path, error));
    TI_CHECK(DeleteFileA(path.c_str()) != FALSE);
    Sleep(1100);
    edr::Event duringFailure = DnsQuery("aa.example.test", 6014, 100 * kSecond);
    automatic.Enrich(duringFailure);
    TI_CHECK(Field(duringFailure, edr::field::kThreatIntelScore) == "60");
    ReplaceFeed(path, SingleIndicatorFeed("domain", "aa.example.test"));
    Sleep(1100);
    edr::Event recovered = DnsQuery("aa.example.test", 6015, 100 * kSecond);
    automatic.Enrich(recovered);
    TI_CHECK(!automatic.ReloadIndicatorsIfChanged(error));
    TI_CHECK(error.empty());
    ReplaceFeed(path, SingleIndicatorFeed("domain", "bb.example.test"));
    Sleep(1100);
    edr::Event newEvent = DnsQuery("bb.example.test", 6016, 100 * kSecond);
    edr::Event disabled = newEvent;
    automatic.Enrich(newEvent);
    manual.Enrich(disabled);
    TI_CHECK(Field(newEvent, edr::field::kThreatIntelScore) == "60");
    TI_CHECK(Field(disabled, edr::field::kThreatIntelScore).empty());
}

void TestReloadConfigBoundaries() {
    std::fprintf(stderr, "[threat_intel] TestReloadConfigBoundaries\n");
    std::string error;
    for (const std::string& seconds : {"0", "1", "86400"}) {
        edr::Config config;
        TI_CHECK(edr::LoadConfigFile(WriteFeed(
            "{\"threat_intel\":{\"reload_poll_seconds\":" + seconds + "}}"), config, error));
        TI_CHECK(config.threatIntelReloadPollSeconds == std::stoul(seconds));
    }
    for (const std::string& invalid : {"-1", "86401", "0.5", "true", "\"5\"", "null"}) {
        edr::Config config;
        TI_CHECK(!edr::LoadConfigFile(WriteFeed(
            "{\"threat_intel\":{\"reload_poll_seconds\":" + invalid + "}}"), config, error));
        TI_CHECK(!error.empty());
    }
    edr::Config defaults;
    TI_CHECK(edr::LoadConfigFile(WriteFeed("{}"), defaults, error));
    TI_CHECK(defaults.threatIntelReloadPollSeconds == 0);
}

void TestAutomaticRecoveryFromMissingOrMalformedStartupFeed() {
    std::fprintf(stderr, "[threat_intel] TestAutomaticRecoveryFromMissingOrMalformedStartupFeed\n");
    for (bool missing : {true, false}) {
        edr::ThreatIntelDetector detector(true, 55, 300, 1024, 1);
        const std::string path = WriteFeed("{");
        if (missing) TI_CHECK(DeleteFileA(path.c_str()) != FALSE);
        std::string error;
        TI_CHECK(!detector.LoadIndicators(path, error));
        TI_CHECK(!error.empty());
        edr::Event before = DnsQuery("c2.example.test", 6020, 100 * kSecond);
        detector.Enrich(before);
        TI_CHECK(Field(before, edr::field::kThreatIntelScore).empty());
        ReplaceFeed(path, kFeed);
        Sleep(1100);
        edr::Event after = DnsQuery("c2.example.test", 6021, 101 * kSecond);
        detector.Enrich(after);
        TI_CHECK(Field(after, edr::field::kThreatIntelScore) == "60");
        TI_CHECK(detector.IndicatorCount() == 4);
        TI_CHECK(detector.FeedName() == "unit-test-feed");
    }
}

void TestCidrAddressBoundaries() {
    std::fprintf(stderr, "[threat_intel] TestCidrAddressBoundaries\n");
    struct Case { const char* type; const char* network; const char* ip; bool match; };
    const Case cases[] = {
        {"ipv4_cidr", "203.0.113.99/25", "203.0.113.0", true},
        {"ipv4_cidr", "203.0.113.99/25", "203.0.113.127", true},
        {"ipv4_cidr", "203.0.113.99/25", "203.0.113.128", false},
        {"ipv4_cidr", "203.0.113.99/25", "203.0.112.255", false},
        {"ipv4_cidr", "203.0.113.7/32", "203.0.113.7", true},
        {"ipv4_cidr", "203.0.113.7/32", "203.0.113.8", false},
        {"ipv4_cidr", "0.0.0.0/0", "255.255.255.255", true},
        {"ipv4_cidr", "0.0.0.0/0", "::ffff:203.0.113.7", false},
        {"ipv6_cidr", "2001:db8:abcd:0:8000::1234/65", "2001:db8:abcd:0:8000::", true},
        {"ipv6_cidr", "2001:db8:abcd:0:8000::/65", "2001:DB8:ABCD:0:FFFF:FFFF:FFFF:FFFF", true},
        {"ipv6_cidr", "2001:db8:abcd:0:8000::/65", "2001:db8:abcd:0:7fff:ffff:ffff:ffff", false},
        {"ipv6_cidr", "2001:db8:abcd:0:8000::/65", "2001:db8:abcd:1::", false},
        {"ipv6_cidr", "2001:db8::7/128", "2001:0db8:0:0:0:0:0:7", true},
        {"ipv6_cidr", "2001:db8::7/128", "2001:db8::8", false},
        {"ipv6_cidr", "::/0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
        {"ipv6_cidr", "::/0", "203.0.113.7", false},
        {"ipv6_cidr", "::ffff:203.0.113.0/120", "::ffff:cb00:717f", true},
        {"ipv6_cidr", "::ffff:203.0.113.0/120", "::ffff:203.0.114.1", false},
        {"ipv4_cidr", " 203.0.113.0/24 ", " 203.0.113.7 ", true},
    };
    for (const Case& item : cases) {
        edr::ThreatIntelDetector detector(true, 55, 300, 1024);
        std::string error;
        TI_CHECK(detector.LoadIndicators(WriteFeed(
            SingleIndicatorFeed(item.type, item.network, "TI-range")), error));
        edr::Event event = NetConnect(item.ip, 6100, 100 * kSecond);
        detector.Enrich(event);
        TI_CHECK(Field(event, edr::field::kThreatIntelScore) == (item.match ? "65" : ""));
        TI_CHECK(Field(event, edr::field::kThreatIntelIocIds) == (item.match ? "TI-range" : ""));
        if (item.match) {
            TI_CHECK(Field(event, edr::field::kThreatIntelIocTypes) ==
                (std::string(item.type) == "ipv4_cidr" ? "ipv4" : "ipv6"));
        }
    }
}

const char* const kOverlappingCidrFeed = R"({"indicators":[
    {"id":"exact","type":"ipv4","value":"203.0.113.7","confidence":"high","source":"unit"},
    {"id":"wide","type":"ipv4_cidr","value":"203.0.113.0/24","confidence":"high","source":"unit"},
    {"id":"narrow","type":"ipv4_cidr","value":"203.0.113.0/25","confidence":"high","source":"unit"},
    {"id":"dns","type":"domain","value":"c2.example.test","confidence":"high","source":"unit"}
]})";

void TestCidrOverlapDoesNotInflateScore() {
    std::fprintf(stderr, "[threat_intel] TestCidrOverlapDoesNotInflateScore\n");
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    std::string error;
    TI_CHECK(detector.LoadIndicators(WriteFeed(kOverlappingCidrFeed), error));
    edr::Event event = NetConnect("203.0.113.7", 6101, 100 * kSecond);
    SetReliableProcessIdentity(event, 1234, "endpoint-A", "ETW");
    detector.Enrich(event);
    TI_CHECK(Field(event, edr::field::kThreatIntelScore) == "65");
    TI_CHECK(Field(event, edr::field::kThreatIntelIocIds) == "exact,wide,narrow");
    TI_CHECK(Field(event, edr::field::kThreatIntelIocCount) == "3");
    edr::Event dns = DnsQuery("c2.example.test", 6101, 101 * kSecond);
    SetReliableProcessIdentity(dns, 1234, "endpoint-A", "ETW");
    detector.Enrich(dns);
    TI_CHECK(Field(dns, edr::field::kThreatIntelScore) == "80");
    for (uint64_t second = 102; second < 105; ++second) {
        edr::Event repeated = NetConnect("203.0.113.7", 6101, second * kSecond);
        SetReliableProcessIdentity(repeated, 1234, "endpoint-A", "ETW");
        detector.Enrich(repeated);
        TI_CHECK(Field(repeated, edr::field::kThreatIntelScore) == "80");
        TI_CHECK(Field(repeated, edr::field::kThreatIntelIocCount) == "4");
    }
}

void TestMalformedCidrPreservesFeed() {
    std::fprintf(stderr, "[threat_intel] TestMalformedCidrPreservesFeed\n");
    const std::pair<const char*, const char*> cases[] = {
        {"ipv4_cidr", "203.0.113.0"}, {"ipv4_cidr", "203.0.113.0/"},
        {"ipv4_cidr", "203.0.113.0/33"}, {"ipv4_cidr", "203.0.113.0/-1"},
        {"ipv4_cidr", "203.0.113.0/+24"}, {"ipv4_cidr", "203.0.113.0/24x"},
        {"ipv4_cidr", "203.0.113.0/24/1"}, {"ipv4_cidr", "203.0.113.0/024"},
        {"ipv4_cidr", "203.0.113.0/ 24"}, {"ipv4_cidr", "203.0.113.0 /24"},
        {"ipv4_cidr", "203.0.113.0/99999999999999999999"},
        {"ipv4_cidr", "203.000.113.0/24"}, {"ipv4_cidr", "256.0.0.0/8"},
        {"ipv4_cidr", "2001:db8::/32"}, {"ipv6_cidr", "203.0.113.0/24"},
        {"ipv6_cidr", "2001:db8::/129"}, {"ipv6_cidr", "2001::db8::/32"},
        {"ipv6_cidr", "fe80::%3/64"}, {"ipv6_cidr", "[2001:db8::]/32"},
        {"ipv6_cidr", "2001:db8::\\u0000ignored/32"},
        {"ipv4_cidr", "203.0.113.0/24\\u0000ignored"},
    };
    edr::ThreatIntelDetector detector = Loaded();
    for (const auto& item : cases) {
        std::string error;
        TI_CHECK(!detector.LoadIndicators(WriteFeed(
            SingleIndicatorFeed(item.first, item.second)), error));
        TI_CHECK(!error.empty());
        edr::Event event = NetConnect("203.0.113.77", 6102, 100 * kSecond);
        detector.Enrich(event);
        TI_CHECK(Field(event, edr::field::kThreatIntelIocIds) == "TI-4");
    }
}

void TestRepeatedExactAddressDoesNotRepeatCrossTypeBonus() {
    std::fprintf(stderr, "[threat_intel] TestRepeatedExactAddressDoesNotRepeatCrossTypeBonus\n");
    edr::ThreatIntelDetector detector = Loaded();
    edr::Event dns = DnsQuery("c2.example.test", 6105, 100 * kSecond);
    SetReliableProcessIdentity(dns, 1234, "endpoint-A", "ETW");
    detector.Enrich(dns);
    for (uint64_t second = 101; second < 105; ++second) {
        edr::Event event = NetConnect("203.0.113.77", 6105, second * kSecond);
        SetReliableProcessIdentity(event, 1234, "endpoint-A", "ETW");
        detector.Enrich(event);
        TI_CHECK(Field(event, edr::field::kThreatIntelScore) == "80");
        TI_CHECK(Field(event, edr::field::kThreatIntelIocCount) == "2");
    }
}

void TestDuplicateCidrNetworksRejected() {
    std::fprintf(stderr, "[threat_intel] TestDuplicateCidrNetworksRejected\n");
    for (const std::string& feed : {
        R"({"indicators":[{"id":"a","type":"ipv4_cidr","value":"203.0.113.0/24","confidence":"high","source":"unit"},{"id":"b","type":"ipv4_cidr","value":"203.0.113.77/24","confidence":"high","source":"unit"}]})",
        R"({"indicators":[{"id":"a","type":"ipv6_cidr","value":"2001:db8::/32","confidence":"high","source":"unit"},{"id":"b","type":"ipv6_cidr","value":"2001:0DB8:0:0:0:0:0:7/32","confidence":"high","source":"unit"}]})"}) {
        edr::ThreatIntelDetector detector(true, 55, 300, 1024);
        std::string error;
        TI_CHECK(!detector.LoadIndicators(WriteFeed(feed), error));
        TI_CHECK(error.find("duplicate") != std::string::npos);
        TI_CHECK(detector.IndicatorCount() == 0);
    }
}

void TestInvalidAddressesDoNotMatchUniversalCidr() {
    std::fprintf(stderr, "[threat_intel] TestInvalidAddressesDoNotMatchUniversalCidr\n");
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    std::string error;
    TI_CHECK(detector.LoadIndicators(WriteFeed(R"({"indicators":[
        {"id":"v4","type":"ipv4_cidr","value":"0.0.0.0/0","confidence":"high","source":"unit"},
        {"id":"v6","type":"ipv6_cidr","value":"::/0","confidence":"high","source":"unit"}
    ]})"), error));
    for (const std::string& ip : {std::string(), std::string("203.0.113.7:80"),
        std::string("203.0.113.7/24"), std::string("203.000.113.7"),
        std::string("[2001:db8::7]:80"), std::string("2001::db8::7"),
        std::string("fe80::1%3"), std::string("203.0.113.7\0bad", 15),
        std::string("2001:db8::7\0bad", 14)}) {
        edr::Event event = NetConnect(ip, 6103, 100 * kSecond);
        detector.Enrich(event);
        TI_CHECK(Field(event, edr::field::kThreatIntelScore).empty());
    }
}

void TestCidrReloadReplacesPrefixesAtomically() {
    std::fprintf(stderr, "[threat_intel] TestCidrReloadReplacesPrefixesAtomically\n");
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    const std::string path = WriteFeed(SingleIndicatorFeed("ipv4_cidr", "203.0.113.0/24", "old"));
    std::string error;
    TI_CHECK(detector.LoadIndicators(path, error));
    ReplaceFeed(path, SingleIndicatorFeed("ipv4_cidr", "203.0.113.0/33"));
    TI_CHECK(!detector.ReloadIndicatorsIfChanged(error));
    edr::Event old = NetConnect("203.0.113.7", 6104, 100 * kSecond);
    SetReliableProcessIdentity(old, 1234, "endpoint-A", "ETW");
    detector.Enrich(old);
    TI_CHECK(Field(old, edr::field::kThreatIntelIocIds) == "old");
    TI_CHECK(detector.StateCount() == 1);
    ReplaceFeed(path, SingleIndicatorFeed("ipv6_cidr", "2001:db8::/32", "new"));
    TI_CHECK(detector.ReloadIndicatorsIfChanged(error));
    TI_CHECK(error.empty());
    TI_CHECK(detector.StateCount() == 0);
    edr::Event removed = NetConnect("203.0.113.7", 6104, 101 * kSecond);
    SetReliableProcessIdentity(removed, 1234, "endpoint-A", "ETW");
    detector.Enrich(removed);
    TI_CHECK(Field(removed, edr::field::kThreatIntelScore).empty());
    edr::Event current = NetConnect("2001:db8::7", 6104, 101 * kSecond);
    SetReliableProcessIdentity(current, 1234, "endpoint-A", "ETW");
    detector.Enrich(current);
    TI_CHECK(Field(current, edr::field::kThreatIntelIocIds) == "new");
}

} // namespace

void RunThreatIntelDetectorTests() {
    TestConcurrentFeedNamespaceIsolation();
    TestCidrAddressBoundaries();
    TestCidrOverlapDoesNotInflateScore();
    TestRepeatedExactAddressDoesNotRepeatCrossTypeBonus();
    TestMalformedCidrPreservesFeed();
    TestDuplicateCidrNetworksRejected();
    TestInvalidAddressesDoNotMatchUniversalCidr();
    TestCidrReloadReplacesPrefixesAtomically();
    TestRejectedReplacementPreservesActiveFeed();
    TestSuccessfulReplacementClearsOldEvidence();
    TestReloadDetectsSameSizeAndTimestampReplacement();
    TestUnchangedAndInvalidReloadRetainProcessEvidence();
    TestMissingFeedRecoversWithoutRestart();
    TestEmptyAndOversizedReplacementsPreserveFeed();
    TestAutomaticReloadIsOptInAndRecoversReadErrors();
    TestReloadConfigBoundaries();
    TestAutomaticRecoveryFromMissingOrMalformedStartupFeed();
    TestSha256HashMatch();
    TestHashesListMatch();
    TestImageChecksumMatch();
    TestDomainExactMatch();
    TestDomainSubdomainAndCaseMatch();
    TestDomainBoundaryNotMatched();
    TestAddressMatch();
    TestCrossTypeBonus();
    TestMinScoreSuppressesAnnotation();
    TestMinScoreBoundary();
    TestUnrelatedEventIgnored();
    TestMalformedFeedRejected();
    TestUnknownIndicatorFieldRejected();
    TestMissingFeedRejected();
    TestStateCapacityBounded();
    TestStateExpiry();
    TestDisabledDetectorInert();
    TestBareArrayFeed();
    TestIpv6EquivalentSpellingsMatch();
    TestIpv4MappedIpv6RemainsIpv6();
    TestIpv6EquivalentIndicatorsRejectedAsDuplicate();
    TestMalformedIpv6IndicatorsRejected();
    TestIpv6EventWithEmbeddedNulDoesNotMatchValidPrefix();
    TestReliableProcessIdentityAccumulatesAcrossProviders();
    TestDifferentProcessInstanceDoesNotInheritIocs();
    TestSameExactIdentityDoesNotIncreaseStateCount();
    TestNewExactIdentityReclaimsOldState();
    TestDifferentEndpointDoesNotInheritIocs();
    TestOpaqueIdentityIsScopedToSource();
    TestUnreliableIdentityIsEventLocalAndCannotPolluteState();
    TestOpaqueIdentityWithoutSourceIsEventLocal();
    TestOpaqueIdentityKeyLengthPrefixesPreventDelimiterCollision();
    std::fprintf(stderr, "[threat_intel] all passed\n");
}

void RunThreatIntelCidrRuleTests(const char* rulesPath) {
    std::fprintf(stderr, "[threat_intel] TestCidrProductionRuleIntegration\n");
    edr::RuleEngine engine;
    engine.LoadFromFile(rulesPath);
    edr::ThreatIntelDetector detector(true, 55, 300, 1024);
    std::string error;
    TI_CHECK(detector.LoadIndicators(WriteFeed(R"({"indicators":[
        {"id":"v4","type":"ipv4_cidr","value":"203.0.113.0/24","confidence":"high","source":"unit"},
        {"id":"v6","type":"ipv6_cidr","value":"2001:db8::/32","confidence":"high","source":"unit"},
        {"id":"hash","type":"sha256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","confidence":"high","source":"unit"}
    ]})"), error));
    size_t networkAlerts = 0, hashAlerts = 0;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        if (alert.ruleId == "EDR-440") { ++networkAlerts; TI_CHECK(alert.action == "alert"); }
        if (alert.ruleId == "EDR-439") { ++hashAlerts; TI_CHECK(alert.action == "alert"); }
    });
    for (const char* ip : {"203.0.113.7", "2001:db8::7"}) {
        edr::Event event = NetConnect(ip, 6106, 100 * kSecond);
        detector.Enrich(event);
        engine.OnEvent(event);
    }
    TI_CHECK(networkAlerts == 2);
    TI_CHECK(hashAlerts == 0);
    edr::Event outside = NetConnect("203.0.114.7", 6106, 101 * kSecond);
    detector.Enrich(outside);
    engine.OnEvent(outside);
    TI_CHECK(networkAlerts == 2);
    edr::Event process = ProcessStart("sample.exe", "sample.exe", std::string(64, 'a'),
        6106, 102 * kSecond);
    SetReliableProcessIdentity(process, 1234, "endpoint-A", "ETW");
    detector.Enrich(process);
    engine.OnEvent(process);
    TI_CHECK(hashAlerts == 0);
    edr::Event connect = NetConnect("203.0.113.7", 6106, 103 * kSecond);
    SetReliableProcessIdentity(connect, 1234, "endpoint-A", "ETW");
    detector.Enrich(connect);
    engine.OnEvent(connect);
    TI_CHECK(hashAlerts == 1);
    TI_CHECK(networkAlerts == 3);
    std::fprintf(stderr, "[threat_intel] production rule integration passed\n");
}
