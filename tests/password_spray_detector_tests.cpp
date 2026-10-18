/*
 * password_spray_detector_tests.cpp - Unit tests for PasswordSprayDetector.
 */
#include "password_spray_detector_tests.h"

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "config.h"
#include "edr_event.h"
#include "event_bus.h"
#include "password_spray_detector.h"
#include "rule_engine.h"

namespace {

#define PS_CHECK(condition) Check((condition), #condition, __LINE__)

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        throw std::runtime_error(
            "password spray detector test failed at line " +
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

edr::Event Logon(const char* operation, const char* srcIp,
                 const char* user, const char* domain,
                 const char* logonType, uint64_t ts100ns) {
    edr::Event event;
    event.type = EDR_EVT_LOGON;
    event.ts100ns = ts100ns;
    event.fields[edr::field::kType] = "LOGON";
    event.fields[edr::field::kOperationType] = operation;
    if (srcIp) event.fields[edr::field::kSrcIp] = srcIp;
    if (user) event.fields[edr::field::kTargetUser] = user;
    if (domain) event.fields[edr::field::kTargetDomain] = domain;
    if (logonType) event.fields[edr::field::kLogonType] = logonType;
    return event;
}

edr::Event Failure(const char* srcIp, const char* user, uint64_t ts100ns,
                   const char* domain = "CORP", const char* logonType = "3") {
    return Logon("LOGON_FAILURE", srcIp, user, domain, logonType, ts100ns);
}

edr::Event Success(const char* srcIp, const char* user, uint64_t ts100ns,
                   const char* domain = "CORP", const char* logonType = "3") {
    return Logon("LOGON", srcIp, user, domain, logonType, ts100ns);
}

void TestInspectsAndDisabled() {
    PS_CHECK(edr::PasswordSprayDetector::Inspects(EDR_EVT_LOGON));
    PS_CHECK(!edr::PasswordSprayDetector::Inspects(EDR_EVT_PROCESS_START));

    edr::PasswordSprayDetector detector(false, 300, 32, 3, 3, 600, 60, 16);
    for (int i = 0; i < 4; ++i) {
        std::string user = "user" + std::to_string(i);
        edr::Event event = Failure("10.0.0.5", user.c_str(),
                                   100000000000ULL + i * 10000000ULL);
        detector.Enrich(event);
        PS_CHECK(!HasField(event, edr::field::kPasswordSprayScore));
    }
    PS_CHECK(detector.StateCount() == 0);
}

void TestDistinctUsersAndThreshold() {
    const uint64_t base = 200000000000ULL;
    edr::PasswordSprayDetector detector(true, 300, 32, 5, 3, 600, 60, 16);

    /* Repeating one account never satisfies the distinct-user threshold. */
    for (int i = 0; i < 5; ++i) {
        edr::Event repeated = Failure("10.0.0.6", "alice", base + i * 10000000ULL);
        detector.Enrich(repeated);
        PS_CHECK(!HasField(repeated, edr::field::kPasswordSprayScore));
    }

    edr::PasswordSprayDetector spray(true, 300, 32, 5, 3, 600, 60, 16);
    const char* users[] = {"alice", "bob", "carol", "alice", "bob"};
    edr::Event last;
    for (int i = 0; i < 5; ++i) {
        last = Failure("10.0.0.7", users[i], base + i * 10000000ULL);
        spray.Enrich(last);
    }
    PS_CHECK(last.fields.at(edr::field::kPasswordSprayScore) == "40");
    PS_CHECK(last.fields.at(edr::field::kPasswordSprayFailures) == "5");
    PS_CHECK(last.fields.at(edr::field::kPasswordSprayUserCount) == "3");
    PS_CHECK(last.fields.at(edr::field::kPasswordSpraySrcIp) == "10.0.0.7");
    PS_CHECK(last.fields.at(edr::field::kPasswordSprayWindowSeconds) == "300");
    const std::string names = last.fields.at(edr::field::kPasswordSprayUsers);
    PS_CHECK(names.find("corp\\alice") != std::string::npos);
    PS_CHECK(names.find("corp\\bob") != std::string::npos);
    PS_CHECK(names.find("corp\\carol") != std::string::npos);
}

void TestSuccessAfterSprayAndDedup() {
    const uint64_t base = 300000000000ULL;
    edr::PasswordSprayDetector detector(true, 300, 32, 3, 3, 120, 60, 16);
    for (int i = 0; i < 3; ++i) {
        const std::string user = "victim" + std::to_string(i + 1);
        edr::Event failure = Failure("10.0.0.8", user.c_str(),
                                     base + i * 10000000ULL);
        detector.Enrich(failure);
    }

    edr::Event success = Success("10.0.0.8", "victim2",
                                 base + 22 * 10000000ULL);
    detector.Enrich(success);
    PS_CHECK(success.fields.at(edr::field::kPasswordSprayScore) == "100");
    PS_CHECK(success.fields.at(edr::field::kPasswordSpraySuccess) == "true");
    PS_CHECK(success.fields.at(edr::field::kPasswordSpraySuccessUser) ==
             "corp\\victim2");
    PS_CHECK(success.fields.at(edr::field::kPasswordSpraySuccessDelaySeconds) ==
             "20");
    PS_CHECK(success.fields.at(edr::field::kPasswordSprayFailures) == "3");

    /* The same successful account is reported only once for this spray. */
    edr::Event duplicate = Success("10.0.0.8", "victim2",
                                   base + 23 * 10000000ULL);
    detector.Enrich(duplicate);
    PS_CHECK(!HasField(duplicate, edr::field::kPasswordSpraySuccess));

    /* Success for an account that was not in the spray is unrelated. */
    edr::Event unrelated = Success("10.0.0.8", "other",
                                   base + 24 * 10000000ULL);
    detector.Enrich(unrelated);
    PS_CHECK(!HasField(unrelated, edr::field::kPasswordSpraySuccess));

    /* Follow-up correlation expires independently of source state. */
    edr::Event late = Success("10.0.0.8", "victim1",
                              base + 200 * 10000000ULL);
    detector.Enrich(late);
    PS_CHECK(!HasField(late, edr::field::kPasswordSpraySuccess));
}

void TestWindowIsolationAndBounds() {
    const uint64_t base = 400000000000ULL;
    edr::PasswordSprayDetector detector(true, 60, 2, 2, 2, 120, 0, 3);

    edr::Event first = Failure("10.0.0.10", "u1", base);
    detector.Enrich(first);
    edr::Event otherSource = Failure("10.0.0.11", "u2", base + 10000000ULL);
    detector.Enrich(otherSource);
    PS_CHECK(!HasField(otherSource, edr::field::kPasswordSprayScore));

    /* Third source evicts the oldest source state. */
    edr::Event thirdSource = Failure("10.0.0.12", "u3", base + 20000000ULL);
    detector.Enrich(thirdSource);
    PS_CHECK(detector.StateCount() <= 2);

    /* Per-source observation cap remains enforced while recent values rotate. */
    edr::PasswordSprayDetector capped(true, 300, 4, 3, 3, 120, 0, 3);
    for (int i = 0; i < 5; ++i) {
        std::string user = "cap" + std::to_string(i);
        edr::Event value = Failure("10.0.0.13", user.c_str(),
                                   base + i * 10000000ULL);
        capped.Enrich(value);
        if (i == 2) PS_CHECK(HasField(value, edr::field::kPasswordSprayScore));
    }
    PS_CHECK(capped.ObservationCount("10.0.0.13") <= 3);

    /* A source idle beyond the failure window starts a fresh sequence. */
    edr::PasswordSprayDetector expiring(true, 60, 4, 2, 2, 120, 0, 8);
    edr::Event old = Failure("10.0.0.14", "old", base);
    expiring.Enrich(old);
    edr::Event fresh = Failure("10.0.0.14", "fresh",
                               base + 700000000ULL);
    expiring.Enrich(fresh);
    PS_CHECK(!HasField(fresh, edr::field::kPasswordSprayScore));
}

void TestOrderingCooldownAndEpisodeBoundaries() {
    const uint64_t base = 500000000000ULL;

    /* A timestamp rollback is rejected before it can borrow future evidence. */
    edr::PasswordSprayDetector ordered(true, 300, 8, 3, 3, 60, 300, 16);
    edr::Event first = Failure("10.0.0.15", "u1", base);
    ordered.Enrich(first);
    edr::Event future = Failure("10.0.0.15", "u3",
                                base + 30 * 10000000ULL);
    ordered.Enrich(future);
    edr::Event late = Failure("10.0.0.15", "u2",
                              base + 20 * 10000000ULL);
    ordered.Enrich(late);
    PS_CHECK(!HasField(late, edr::field::kPasswordSprayScore));
    PS_CHECK(ordered.ObservationCount("10.0.0.15") == 2);
    edr::Event crossing = Failure("10.0.0.15", "u2",
                                  base + 40 * 10000000ULL);
    ordered.Enrich(crossing);
    PS_CHECK(HasField(crossing, edr::field::kPasswordSprayScore));

    /* A future timestamp on another source must not expire this source. */
    edr::PasswordSprayDetector isolated(true, 60, 8, 2, 2, 60, 300, 8);
    edr::Event a1 = Failure("10.0.0.16", "u1", base);
    isolated.Enrich(a1);
    edr::Event skew = Failure("10.0.0.17", "other",
                              base + 86400ULL * 10000000ULL);
    isolated.Enrich(skew);
    edr::Event a2 = Failure("10.0.0.16", "u2",
                            base + 10 * 10000000ULL);
    isolated.Enrich(a2);
    PS_CHECK(HasField(a2, edr::field::kPasswordSprayScore));

    /* Zero dedup disables cooldown rather than suppressing repeat stamps. */
    edr::PasswordSprayDetector noCooldown(true, 300, 8, 2, 2, 60, 0, 8);
    edr::Event d1 = Failure("10.0.0.18", "u1", base);
    noCooldown.Enrich(d1);
    edr::Event d2 = Failure("10.0.0.18", "u2", base + 10000000ULL);
    noCooldown.Enrich(d2);
    PS_CHECK(HasField(d2, edr::field::kPasswordSprayScore));
    edr::Event d3 = Failure("10.0.0.18", "u3", base + 20000000ULL);
    noCooldown.Enrich(d3);
    PS_CHECK(HasField(d3, edr::field::kPasswordSprayScore));

    /* Later attacked accounts join the fixed-length episode, but repeat
     * failures never move the episode's original start time. */
    edr::PasswordSprayDetector episode(true, 300, 8, 2, 2, 30, 0, 8);
    edr::Event e1 = Failure("10.0.0.19", "u1", base);
    episode.Enrich(e1);
    edr::Event e2 = Failure("10.0.0.19", "u2", base + 10000000ULL);
    episode.Enrich(e2);
    edr::Event e3 = Failure("10.0.0.19", "u3",
                            base + 20 * 10000000ULL);
    episode.Enrich(e3);
    edr::Event included = Success("10.0.0.19", "u3",
                                  base + 25 * 10000000ULL);
    episode.Enrich(included);
    PS_CHECK(HasField(included, edr::field::kPasswordSpraySuccess));
    edr::Event expiredRepeat = Failure("10.0.0.19", "u4",
                                       base + 35 * 10000000ULL);
    episode.Enrich(expiredRepeat);
    edr::Event notExtended = Success("10.0.0.19", "u1",
                                     base + 36 * 10000000ULL);
    episode.Enrich(notExtended);
    PS_CHECK(!HasField(notExtended, edr::field::kPasswordSpraySuccess));
}

void TestNoiseFiltersAndBoundedNormalization() {
    const uint64_t base = 600000000000ULL;
    edr::PasswordSprayDetector detector(true, 300, 16, 2, 2, 120, 0, 16);
    const std::string longIp(65, '1');
    const std::string longUser(257, 'u');
    const std::string longDomain(257, 'd');
    std::vector<edr::Event> ignored = {
        Failure("-", "alice", base),
        Failure("127.0.0.1", "bob", base + 10000000ULL),
        Failure("::ffff:127.0.0.1", "bob", base + 20000000ULL),
        Failure("10.0.0.20", "HOST01$", base + 30000000ULL),
        Failure("10.0.0.20", "HOST02$@CORP.LOCAL", base + 40000000ULL),
        Failure("10.0.0.20", "alice", base + 50000000ULL, "CORP", "2"),
        Logon("LOGON_ELEVATED", "10.0.0.20", "bob", "CORP", "3",
              base + 60000000ULL),
        Failure(longIp.c_str(), "user", base + 70000000ULL),
        Failure("10.0.0.20", longUser.c_str(), base + 80000000ULL),
        Failure("10.0.0.20", "user", base + 90000000ULL,
                longDomain.c_str())};
    for (edr::Event& event : ignored) {
        detector.Enrich(event);
        PS_CHECK(!HasField(event, edr::field::kPasswordSprayScore));
    }
    PS_CHECK(detector.StateCount() == 0);

    /* IPv4-mapped IPv6 and ordinary IPv4 canonicalize to one source key. */
    edr::Event mapped = Failure("::ffff:10.0.0.21", "u1", base);
    detector.Enrich(mapped);
    edr::Event plain = Failure("10.0.0.21", "u2", base + 10000000ULL);
    detector.Enrich(plain);
    PS_CHECK(HasField(plain, edr::field::kPasswordSprayScore));
    PS_CHECK(plain.fields.at(edr::field::kPasswordSpraySrcIp) == "10.0.0.21");

    /* Sixteen maximum-length identities still serialize under the 4 KiB cap. */
    edr::PasswordSprayDetector summary(true, 300, 16, 2, 2, 120, 0, 16);
    for (int i = 0; i < 16; ++i) {
        const std::string user = "u" + std::to_string(i) + std::string(240, 'a');
        const std::string domain = "d" + std::to_string(i) + std::string(240, 'b');
        edr::Event value = Failure("10.0.0.22", user.c_str(),
                                   base + i * 10000000ULL, domain.c_str());
        summary.Enrich(value);
        if (i >= 1) {
            PS_CHECK(value.fields.at(edr::field::kPasswordSprayUsers).size()
                     <= 4096);
        }
    }
}

void TestConfigStrictAtomic() {
    const char* path = "edr-native-password-spray-config.json";
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"password_spray":{"enable":true,"window_seconds":900,"state_capacity":512,"min_failures":12,"min_distinct_users":6,"success_followup_seconds":300,"dedup_seconds":120,"max_failures_per_source":64}})";
    }
    edr::Config config;
    std::string error;
    PS_CHECK(edr::LoadConfigFile(path, config, error));
    PS_CHECK(config.passwordSprayEnable);
    PS_CHECK(config.passwordSprayWindowSeconds == 900);
    PS_CHECK(config.passwordSprayStateCapacity == 512);
    PS_CHECK(config.passwordSprayMinFailures == 12);
    PS_CHECK(config.passwordSprayMinDistinctUsers == 6);
    PS_CHECK(config.passwordSpraySuccessFollowupSeconds == 300);
    PS_CHECK(config.passwordSprayDedupSeconds == 120);
    PS_CHECK(config.passwordSprayMaxFailuresPerSource == 64);

    for (const char* invalid : {
             R"({"password_spray":true})",
             R"({"password_spray":{"unknown":1}})",
             R"({"password_spray":{"min_distinct_users":1}})",
             R"({"password_spray":{"min_failures":1}})",
             R"({"password_spray":{"state_capacity":63}})",
             R"({"password_spray":{"max_failures_per_source":7,"min_failures":8}})",
             R"({"password_spray":{"max_failures_per_source":7,"min_distinct_users":8}})"}) {
        std::ofstream out(path, std::ios::binary);
        out << invalid;
        out.close();
        edr::Config unchanged;
        unchanged.passwordSprayEnable = true;
        unchanged.passwordSprayMinFailures = 99;
        PS_CHECK(!edr::LoadConfigFile(path, unchanged, error));
        PS_CHECK(unchanged.passwordSprayEnable);
        PS_CHECK(unchanged.passwordSprayMinFailures == 99);
    }
    DeleteFileA(path);
}

void TestProductionRules() {
    edr::RuleEngine engine;
    engine.LoadFromFile(ProductionRulesPath());
    std::vector<std::string> hits;
    engine.SetAlertCallback(
        [&](const edr::Alert& alert) { hits.push_back(alert.ruleId); });

    edr::Event spray = Failure("10.0.0.30", "user", 0);
    spray.fields[edr::field::kPasswordSprayScore] = "60";
    spray.fields[edr::field::kPasswordSprayFailures] = "10";
    spray.fields[edr::field::kPasswordSprayUserCount] = "5";
    engine.OnEvent(spray);
    PS_CHECK(Has(hits, "EDR-252"));
    PS_CHECK(!Has(hits, "EDR-253"));

    hits.clear();
    edr::Event success = Success("10.0.0.30", "user", 0);
    success.fields[edr::field::kPasswordSprayScore] = "100";
    success.fields[edr::field::kPasswordSpraySuccess] = "true";
    engine.OnEvent(success);
    PS_CHECK(!Has(hits, "EDR-252"));
    PS_CHECK(Has(hits, "EDR-253"));
}

} // namespace

void RunPasswordSprayDetectorTests() {
    TestInspectsAndDisabled();
    TestDistinctUsersAndThreshold();
    TestSuccessAfterSprayAndDedup();
    TestWindowIsolationAndBounds();
    TestOrderingCooldownAndEpisodeBoundaries();
    TestNoiseFiltersAndBoundedNormalization();
    TestConfigStrictAtomic();
    TestProductionRules();
}
