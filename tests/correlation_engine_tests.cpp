/*
 * correlation_engine_tests.cpp - Unit tests for CorrelationEngine.
 *
 * Each test builds Alert values directly (with a live Event owned by the
 * test) so the correlator's entity logic is exercised without running the
 * rule engine. The Event must outlive the Alert, which the local scope
 * guarantees.
 *
 * Score reference: severity weight (critical 90 / high 75 / medium 50 /
 * low 25 / info 10) plus 5 per additional distinct tactic, capped at +20.
 */
#include "correlation_engine_tests.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

#include "correlation_engine.h"
#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"

namespace {

#define CE_CHECK(cond) Check((cond), #cond, __LINE__)

void Check(bool cond, const char* expr, int line) {
    if (!cond) {
        throw std::runtime_error(
            "correlation engine test failed at line " +
            std::to_string(line) + ": " + expr);
    }
}

constexpr uint64_t kSecond = 10000000ULL;
constexpr uint32_t kPid = 9000;

edr::Event Event(uint32_t pid, uint64_t ts100ns) {
    edr::Event ev;
    ev.type = EDR_EVT_PROCESS_START;
    ev.pid = pid;
    ev.ts100ns = ts100ns;
    ev.processStartTime100ns = 1000 * kSecond + pid;
    ev.fields[edr::field::kType] = "PROCESS_START";
    ev.fields[edr::field::kImage] =
        "C:\\Users\\victim\\AppData\\Local\\Temp\\dropper.exe";
    return ev;
}

edr::Alert Alert(const edr::Event* event, const std::string& rule,
                 const std::string& severity,
                 const std::vector<std::string>& tactics) {
    edr::Alert alert;
    alert.ruleId = rule;
    alert.severity = severity;
    alert.action = "alert";
    alert.event = event;
    alert.mitreTactic = tactics;
    return alert;
}

void TestIncidentIdsRemainDistinctAcrossEngineRestart() {
    std::fprintf(stderr, "[correlation] TestIncidentIdsRemainDistinctAcrossEngineRestart\n");
    edr::CorrelationEngine first(true, 1800, 256, 2);
    edr::CorrelationEngine restarted(true, 1800, 256, 2);
    edr::Event event = Event(kPid, 100 * kSecond);
    const auto alert = Alert(&event, "EDR-001", "high", {"Execution"});
    const auto original = first.Observe(alert);
    const auto nextRun = restarted.Observe(alert);
    CE_CHECK(!original.incidentId.empty());
    CE_CHECK(original.incidentId != nextRun.incidentId);
    CE_CHECK(first.Observe(alert).incidentId == original.incidentId);
}

void TestRunIdFactoryFailure() {
    for (const std::string id : {std::string(), std::string(32, 'x')}) {
        bool rejected = false;
        try { edr::CorrelationEngine engine(true, 1800, 256, 2, [id] { return id; }); }
        catch (const std::runtime_error&) { rejected = true; }
        CE_CHECK(rejected);
    }
    int calls = 0;
    const auto failing = [&calls]() -> std::string {
        ++calls;
        throw std::runtime_error("random source failure");
    };
    bool rejected = false;
    try { edr::CorrelationEngine engine(true, 1800, 256, 2, failing); }
    catch (const std::runtime_error&) { rejected = true; }
    CE_CHECK(rejected && calls == 1);
    edr::CorrelationEngine disabled(false, 1800, 256, 2, failing);
    CE_CHECK(calls == 1);
}

/* Two alerts with the same PID and exact creation time fold into one
 * incident, and the second one must report an alert count of 2. */
void TestSameProcessFolds() {
    std::fprintf(stderr, "[correlation] TestSameProcessFolds\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2);

    edr::Event first = Event(kPid, 100 * kSecond);
    edr::Alert a1 = Alert(&first, "EDR-001", "high", {"Execution"});
    const edr::CorrelationAnnotation r1 = engine.Observe(a1);
    CE_CHECK(!r1.incidentId.empty());
    CE_CHECK(r1.alertCount == 1);
    CE_CHECK(r1.stage == "Execution");
    CE_CHECK(r1.score == 75);

    edr::Event second = Event(kPid, 101 * kSecond);
    edr::Alert a2 = Alert(&second, "EDR-002", "high", {"Persistence"});
    const edr::CorrelationAnnotation r2 = engine.Observe(a2);
    CE_CHECK(r2.incidentId == r1.incidentId);
    CE_CHECK(r2.alertCount == 2);
    CE_CHECK(r2.stageCount == 2);
    /* high(75) + one extra tactic (5) = 80. */
    CE_CHECK(r2.score == 80);
    CE_CHECK(r2.tactics == "Execution,Persistence");
    CE_CHECK(engine.IncidentCount() == 1);
}

/* A shared image basename from different paths does not prove that two
 * unrelated process instances belong to one chain. */
void TestImageBasenameDoesNotFold() {
    std::fprintf(stderr, "[correlation] TestImageBasenameDoesNotFold\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2);

    edr::Event first = Event(9101, 100 * kSecond);
    edr::Alert a1 = Alert(&first, "EDR-010", "medium", {"Execution"});
    const edr::CorrelationAnnotation r1 = engine.Observe(a1);

    edr::Event second = Event(9102, 101 * kSecond);
    second.fields[edr::field::kImage] = "C:\\Program Files\\dropper.exe";
    edr::Alert a2 = Alert(&second, "EDR-011", "medium", {"Defense Evasion"});
    const edr::CorrelationAnnotation r2 = engine.Observe(a2);

    CE_CHECK(r2.incidentId != r1.incidentId);
    CE_CHECK(r2.alertCount == 1);
    CE_CHECK(engine.IncidentCount() == 2);
}

/* Alerts with no shared entity stay separate incidents. */
void TestUnrelatedAlertsSeparate() {
    std::fprintf(stderr, "[correlation] TestUnrelatedAlertsSeparate\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2);

    edr::Event first = Event(9201, 100 * kSecond);
    first.fields[edr::field::kImage] = "C:\\Windows\\System32\\cmd.exe";
    edr::Alert a1 = Alert(&first, "EDR-020", "low", {"Discovery"});
    const edr::CorrelationAnnotation r1 = engine.Observe(a1);

    edr::Event second = Event(9202, 100 * kSecond);
    second.fields[edr::field::kImage] = "C:\\Windows\\System32\\net.exe";
    edr::Alert a2 = Alert(&second, "EDR-021", "low", {"Discovery"});
    const edr::CorrelationAnnotation r2 = engine.Observe(a2);

    CE_CHECK(r1.incidentId != r2.incidentId);
    CE_CHECK(engine.IncidentCount() == 2);
}

/* A shared account name alone is not evidence that alerts belong to the same
 * process chain. */
void TestUserOnlyPivotDoesNotFold() {
    std::fprintf(stderr, "[correlation] TestUserOnlyPivotDoesNotFold\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2);

    edr::Event first = Event(9301, 100 * kSecond);
    first.fields[edr::field::kImage] = "C:\\Temp\\a.exe";
    first.fields[edr::field::kSubjectUserName] = "CORP\\victim";
    edr::Alert a1 = Alert(&first, "EDR-030", "high", {"Execution"});
    const edr::CorrelationAnnotation r1 = engine.Observe(a1);

    edr::Event second = Event(9302, 101 * kSecond);
    second.fields[edr::field::kImage] = "C:\\Temp\\b.exe";
    second.fields[edr::field::kSubjectUserName] = "CORP\\victim";
    edr::Alert a2 = Alert(&second, "EDR-031", "high", {"Credential Access"});
    const edr::CorrelationAnnotation r2 = engine.Observe(a2);

    CE_CHECK(r2.incidentId != r1.incidentId);
    CE_CHECK(r2.tactics == "Credential Access");
    CE_CHECK(engine.IncidentCount() == 2);
}

void TestBarePidDoesNotCorrelateAndProcessReuseStaysSeparate() {
    std::fprintf(stderr, "[correlation] TestBarePidDoesNotCorrelateAndProcessReuseStaysSeparate\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2);

    edr::Event bare1 = Event(9380, 100 * kSecond);
    bare1.processStartTime100ns = 0;
    bare1.processIdentity.clear();
    const auto first = engine.Observe(
        Alert(&bare1, "EDR-032", "high", {"Execution"}));

    edr::Event bare2 = bare1;
    bare2.ts100ns += kSecond;
    const auto sameBarePid = engine.Observe(
        Alert(&bare2, "EDR-033", "high", {"Persistence"}));
    CE_CHECK(sameBarePid.incidentId != first.incidentId);

    edr::Event reused = Event(9381, 102 * kSecond);
    reused.processStartTime100ns = 77 * kSecond;
    const auto oldInstance = engine.Observe(
        Alert(&reused, "EDR-034", "high", {"Discovery"}));
    edr::Event replacement = reused;
    replacement.ts100ns += kSecond;
    replacement.processStartTime100ns += 500;
    replacement.processIdentity = "{same-provider-guid-is-not-proof}";
    const auto newInstance = engine.Observe(
        Alert(&replacement, "EDR-035", "high", {"Impact"}));
    CE_CHECK(oldInstance.incidentId != newInstance.incidentId);
}

void TestEndpointScopesStrongAndWeakEntities() {
    std::fprintf(stderr, "[correlation] TestEndpointScopesStrongAndWeakEntities\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2, {}, "local-device");

    edr::Event first = Event(9382, 100 * kSecond);
    first.fields[edr::field::kEndpointId] = "endpoint-a";
    first.fields[edr::field::kSource] = "sysmon";
    first.processIdentity = "{same-guid}";
    const auto a = engine.Observe(
        Alert(&first, "EDR-036", "high", {"Execution"}));

    edr::Event otherEndpoint = first;
    otherEndpoint.fields[edr::field::kEndpointId] = "endpoint-b";
    otherEndpoint.fields[edr::field::kSource] = "etw";
    const auto b = engine.Observe(
        Alert(&otherEndpoint, "EDR-037", "high", {"Persistence"}));
    CE_CHECK(a.incidentId != b.incidentId);
    CE_CHECK(engine.IncidentCount() == 2);
    const auto incidents = engine.Snapshot(4);
    bool sawA = false, sawB = false;
    for (const auto& incident : incidents) {
        if (incident.id == a.incidentId) sawA = incident.host == "endpoint-a";
        if (incident.id == b.incidentId) sawB = incident.host == "endpoint-b";
    }
    CE_CHECK(sawA && sawB);
}

void TestSysmonAndEtwExactInstanceIdentityCorrelates() {
    std::fprintf(stderr, "[correlation] TestSysmonAndEtwExactInstanceIdentityCorrelates\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2, {}, "local-device");
    edr::Event sysmon = Event(9384, 100 * kSecond);
    sysmon.processIdentity = "{sysmon-guid}";
    sysmon.source = "sysmon";
    sysmon.fields[edr::field::kEndpointId] = "endpoint-a";
    const auto first = engine.Observe(
        Alert(&sysmon, "EDR-039", "high", {"Execution"}));

    edr::Event etw = sysmon;
    etw.processIdentity = "sequence@55";
    etw.source = "etw";
    etw.fields[edr::field::kSource] = "etw";
    etw.ts100ns += kSecond;
    const auto duplicateInstance = engine.Observe(
        Alert(&etw, "EDR-039B", "high", {"Persistence"}));
    CE_CHECK(duplicateInstance.incidentId == first.incidentId);
    CE_CHECK(duplicateInstance.alertCount == 2);
}

void TestOpaqueIdentityDoesNotCrossProducerBoundary() {
    std::fprintf(stderr, "[correlation] TestOpaqueIdentityDoesNotCrossProducerBoundary\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2, {}, "local-device");
    edr::Event sysmon = Event(9385, 100 * kSecond);
    sysmon.processStartTime100ns = 0;
    sysmon.processIdentity = "opaque-token";
    sysmon.source = "sysmon";
    const auto first = engine.Observe(
        Alert(&sysmon, "EDR-039C", "high", {"Execution"}));

    edr::Event etw = sysmon;
    etw.ts100ns += kSecond;
    etw.source = "etw";
    etw.fields[edr::field::kSource] = "etw";
    const auto second = engine.Observe(
        Alert(&etw, "EDR-039D", "high", {"Persistence"}));
    CE_CHECK(second.incidentId != first.incidentId);
}

void TestProcessAliasesJoinPartialAndParentEvidence() {
    std::fprintf(stderr, "[correlation] TestProcessAliasesJoinPartialAndParentEvidence\n");
    for (const std::string source : {"sysmon", "etw"}) {
        for (bool partialFirst : {false, true}) {
            edr::CorrelationEngine engine(true, 60, 8, 2);
            edr::Event full = Event(9386, 100 * kSecond);
            full.source = source;
            full.processIdentity = source == "sysmon" ? "{guid-parent}" : "sequence@55";
            edr::Event partial = full;
            partial.processStartTime100ns = 0;
            auto first = engine.Observe(Alert(partialFirst ? &partial : &full,
                "ALIAS-1", "high", {"Execution"}));
            full.ts100ns += kSecond;
            partial.ts100ns += kSecond;
            auto second = engine.Observe(Alert(partialFirst ? &full : &partial,
                "ALIAS-2", "high", {"Persistence"}));
            CE_CHECK(first.incidentId == second.incidentId);
            edr::Event child = Event(9387, 102 * kSecond);
            child.source = source;
            child.parentProcessIdentity = full.processIdentity;
            auto third = engine.Observe(Alert(&child, "ALIAS-3", "high", {"Discovery"}));
            CE_CHECK(third.incidentId == first.incidentId);
            CE_CHECK(third.alertCount == 3 && third.stageCount == 3);
            CE_CHECK(engine.IncidentCount() == 1);
        }
    }
}

void TestProcessAliasScopeConflictAndWeakIdentity() {
    std::fprintf(stderr, "[correlation] TestProcessAliasScopeConflictAndWeakIdentity\n");
    edr::CorrelationEngine engine(true, 60, 32, 2);
    edr::Event full = Event(9386, 100 * kSecond);
    full.source = "sysmon";
    full.processIdentity = "{guid-conflict}";
    full.fields[edr::field::kEndpointId] = "endpoint-a";
    const auto first = engine.Observe(Alert(&full, "ALIAS-1", "high", {}));
    edr::Event partial = full;
    partial.processStartTime100ns = 0;
    partial.source = "etw";
    CE_CHECK(engine.Observe(Alert(&partial, "OTHER-SOURCE", "high", {})).incidentId != first.incidentId);
    partial.source = "sysmon";
    partial.fields[edr::field::kEndpointId] = "endpoint-b";
    CE_CHECK(engine.Observe(Alert(&partial, "OTHER-ENDPOINT", "high", {})).incidentId != first.incidentId);
    edr::Event conflict = full;
    ++conflict.processStartTime100ns;
    const auto different = engine.Observe(Alert(&conflict, "CONFLICT", "high", {}));
    CE_CHECK(different.incidentId != first.incidentId);
    partial = full;
    partial.processStartTime100ns = 0;
    const auto ambiguous = engine.Observe(Alert(&partial, "AMBIGUOUS", "high", {}));
    CE_CHECK(ambiguous.incidentId != first.incidentId);
    CE_CHECK(ambiguous.incidentId != different.incidentId);
    const auto again = engine.Observe(Alert(&partial, "AMBIGUOUS-AGAIN", "high", {}));
    CE_CHECK(again.incidentId != ambiguous.incidentId);
    CE_CHECK(engine.Observe(Alert(&full, "EXACT", "high", {})).incidentId == first.incidentId);
    edr::Event child = Event(9387, 101 * kSecond);
    child.source = "sysmon";
    child.fields[edr::field::kEndpointId] = "endpoint-a";
    child.parentProcessIdentity = full.processIdentity;
    const auto childResult = engine.Observe(Alert(&child, "CHILD", "high", {}));
    CE_CHECK(childResult.incidentId != first.incidentId && childResult.incidentId != different.incidentId);
    for (const std::string weak : {"pid:9386", "9386", "wmi/9386"}) {
        full.processIdentity = weak;
        engine.Observe(Alert(&full, "WEAK-FULL", "high", {}));
        partial = full;
        partial.processStartTime100ns = 0;
        CE_CHECK(engine.Observe(Alert(&partial, "WEAK", "high", {})).incidentId != first.incidentId);
    }
}

void TestProcessAliasCapacityExpiryAndLateEvents() {
    std::fprintf(stderr, "[correlation] TestProcessAliasCapacityExpiryAndLateEvents\n");
    edr::CorrelationEngine engine(true, 60, 2, 2);
    edr::Event full = Event(9386, 100 * kSecond);
    full.source = "sysmon";
    full.processIdentity = "{old-guid}";
    const auto first = engine.Observe(Alert(&full, "ALIAS-1", "high", {}));
    for (int i = 0; i < 3; ++i) {
        edr::Event next = full;
        next.ts100ns += (i + 1) * kSecond;
        next.processIdentity = "{other-" + std::to_string(i) + "}";
        CE_CHECK(engine.Observe(Alert(&next, "FILL", "high", {})).incidentId == first.incidentId);
    }
    edr::Event partial = full;
    partial.processStartTime100ns = 0;
    partial.ts100ns = 104 * kSecond;
    CE_CHECK(engine.Observe(Alert(&partial, "EVICTED", "high", {})).incidentId != first.incidentId);

    edr::CorrelationEngine expiring(true, 60, 16, 2);
    const auto initial = expiring.Observe(Alert(&full, "ALIAS-1", "high", {}));
    edr::Event exact = full;
    exact.processIdentity.clear();
    exact.ts100ns = 150 * kSecond;
    expiring.Observe(Alert(&exact, "KEEP-INCIDENT", "high", {}));
    expiring.FlushExpired(161 * kSecond);
    partial.ts100ns = 161 * kSecond;
    CE_CHECK(expiring.Observe(Alert(&partial, "EXPIRED-ALIAS", "high", {})).incidentId != initial.incidentId);
    const auto stale = expiring.Observe(Alert(&full, "LATE-FULL", "high", {}));
    CE_CHECK(stale.incidentId != initial.incidentId);
    partial.ts100ns = 162 * kSecond;
    CE_CHECK(expiring.Observe(Alert(&partial, "AFTER-LATE", "high", {})).incidentId != initial.incidentId);
}

void TestConflictingAliasCapacityFailsClosed() {
    edr::CorrelationEngine engine(true, 60, 2, 2);
    for (uint32_t i = 0; i < 3; ++i) {
        auto event = Event(100 + i, (100 + i) * kSecond);
        event.source = "sysmon";
        event.processIdentity = "{conflict-" + std::to_string(i) + "}";
        engine.Observe(Alert(&event, "FIRST", "high", {}));
        ++event.processStartTime100ns;
        engine.Observe(Alert(&event, "CONFLICT", "high", {}));
    }
    // An unlimited stream of conflicting aliases must not allocate an
    // unlimited lifetime blocklist. At capacity, opaque correlation stops.
    auto full = Event(999, 110 * kSecond);
    full.source = "sysmon";
    full.processIdentity = "{after-conflict-capacity}";
    const auto exact = engine.Observe(Alert(&full, "EXACT", "high", {}));
    auto partial = full;
    partial.processStartTime100ns = 0;
    const auto weak = engine.Observe(Alert(&partial, "PARTIAL", "high", {}));
    CE_CHECK(exact.incidentId != weak.incidentId);
    full.ts100ns += kSecond;
    CE_CHECK(engine.Observe(Alert(&full, "EXACT-AGAIN", "high", {})).incidentId == exact.incidentId);
}

void TestAliasPromotesAndMergesExistingExactIncident() {
    std::fprintf(stderr, "[correlation] TestAliasPromotesAndMergesExistingExactIncident\n");
    edr::CorrelationEngine engine(true, 60, 16, 2);
    edr::Event full = Event(9386, 100 * kSecond);
    full.source = "sysmon";
    edr::Event partial = full;
    partial.processStartTime100ns = 0;
    partial.processIdentity = "{guid-merge}";
    const auto opaque = engine.Observe(Alert(&partial, "OPAQUE", "high", {"Execution"}));
    const auto exact = engine.Observe(Alert(&full, "EXACT", "high", {"Persistence"}));
    CE_CHECK(opaque.incidentId != exact.incidentId);
    full.processIdentity = partial.processIdentity;
    full.ts100ns += kSecond;
    const auto joined = engine.Observe(Alert(&full, "JOIN", "high", {"Discovery"}));
    CE_CHECK(engine.IncidentCount() == 1);
    CE_CHECK(joined.alertCount == 3 && joined.stageCount == 3);
    CE_CHECK(engine.Observe(Alert(&partial, "LATER", "high", {})).incidentId == joined.incidentId);
}

void TestStrongAliasesRemainIndependentAcrossScopes() {
    std::fprintf(stderr, "[correlation] TestStrongAliasesRemainIndependentAcrossScopes\n");
    edr::CorrelationEngine engine(true, 60, 16, 2);
    edr::Event first = Event(9386, 100 * kSecond);
    first.source = "sysmon";
    first.processIdentity = "{shared-token}";
    first.fields[edr::field::kEndpointId] = "endpoint-a";
    const auto a = engine.Observe(Alert(&first, "A", "high", {}));
    edr::Event other = Event(9387, 101 * kSecond);
    other.source = first.source;
    other.processIdentity = first.processIdentity;
    other.fields[edr::field::kEndpointId] = "endpoint-b";
    const auto b = engine.Observe(Alert(&other, "B", "high", {}));
    other.source = "etw";
    other.fields[edr::field::kEndpointId] = "endpoint-a";
    const auto c = engine.Observe(Alert(&other, "C", "high", {}));
    CE_CHECK(a.incidentId != b.incidentId && a.incidentId != c.incidentId);
    first.processStartTime100ns = 0;
    first.ts100ns = 102 * kSecond;
    CE_CHECK(engine.Observe(Alert(&first, "A-PARTIAL", "high", {})).incidentId == a.incidentId);
    other.processStartTime100ns = 0;
    CE_CHECK(engine.Observe(Alert(&other, "C-PARTIAL", "high", {})).incidentId == c.incidentId);
    other.source = "sysmon";
    other.fields[edr::field::kEndpointId] = "endpoint-b";
    CE_CHECK(engine.Observe(Alert(&other, "B-PARTIAL", "high", {})).incidentId == b.incidentId);
}

void TestLateEvidenceDoesNotRegressIncidentOrAliasTime() {
    std::fprintf(stderr, "[correlation] TestLateEvidenceDoesNotRegressIncidentOrAliasTime\n");
    edr::CorrelationEngine engine(true, 60, 16, 2);
    edr::Event full = Event(9386, 100 * kSecond);
    full.source = "sysmon";
    full.processIdentity = "{refresh-guid}";
    const auto first = engine.Observe(Alert(&full, "FIRST", "high", {"Execution"}));
    full.ts100ns = 150 * kSecond;
    engine.Observe(Alert(&full, "NEWEST", "high", {"Execution"}));
    full.ts100ns = 110 * kSecond;
    const auto late = engine.Observe(Alert(&full, "LATE", "high", {"Execution"}));
    CE_CHECK(late.incidentId == first.incidentId && late.alertCount == 3);
    const auto snapshot = engine.Snapshot(1);
    CE_CHECK(snapshot.size() == 1);
    CE_CHECK(snapshot[0].lastSeen100ns == 150 * kSecond);
    CE_CHECK(snapshot[0].stages[0].lastSeen100ns == 150 * kSecond);
    engine.FlushExpired(171 * kSecond);
    edr::Event partial = full;
    partial.processStartTime100ns = 0;
    partial.ts100ns = 171 * kSecond;
    CE_CHECK(engine.Observe(Alert(&partial, "PARTIAL", "high", {})).incidentId == first.incidentId);
    full.ts100ns = 100 * kSecond;
    CE_CHECK(engine.Observe(Alert(&full, "TOO-OLD", "high", {})).incidentId.empty());
    CE_CHECK(engine.Snapshot(1)[0].alertCount == 4);
}

void TestConflictedAliasRemainsBlockedAfterExpiry() {
    std::fprintf(stderr, "[correlation] TestConflictedAliasRemainsBlockedAfterExpiry\n");
    edr::CorrelationEngine engine(true, 60, 1, 2);
    edr::Event full = Event(9386, 100 * kSecond);
    full.source = "sysmon";
    full.processIdentity = "{conflicted-guid}";
    engine.Observe(Alert(&full, "FIRST", "high", {}));
    ++full.processStartTime100ns;
    full.ts100ns = 101 * kSecond;
    engine.Observe(Alert(&full, "CONFLICT", "high", {}));
    edr::Event other = full;
    other.processIdentity = "{replacement-guid}";
    engine.Observe(Alert(&other, "EVICT", "high", {}));
    engine.FlushExpired(162 * kSecond);
    full.ts100ns = 163 * kSecond;
    const auto exact = engine.Observe(Alert(&full, "EXACT", "high", {}));
    full.processStartTime100ns = 0;
    const auto partial = engine.Observe(Alert(&full, "PARTIAL", "high", {}));
    CE_CHECK(partial.incidentId != exact.incidentId);
}

void TestSourceIsNotEndpointIdentity() {
    std::fprintf(stderr, "[correlation] TestSourceIsNotEndpointIdentity\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2, {}, "agent-host");
    edr::Event event = Event(9383, 100 * kSecond);
    event.fields[edr::field::kSource] = "sysmon";
    const auto result = engine.Observe(
        Alert(&event, "EDR-038", "high", {"Execution"}));
    const auto incidents = engine.Snapshot(1);
    CE_CHECK(incidents.size() == 1);
    CE_CHECK(incidents[0].id == result.incidentId);
    CE_CHECK(incidents[0].host == "agent-host");
}

/* Severity roll-up keeps the highest severity, and the score reflects it. */
void TestSeverityRollup() {
    std::fprintf(stderr, "[correlation] TestSeverityRollup\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2);

    edr::Event first = Event(kPid, 100 * kSecond);
    edr::Alert low = Alert(&first, "EDR-040", "low", {"Discovery"});
    const edr::CorrelationAnnotation r1 = engine.Observe(low);
    CE_CHECK(r1.score == 25);

    edr::Event second = Event(kPid, 101 * kSecond);
    edr::Alert critical = Alert(&second, "EDR-041", "critical",
                                {"Impact"});
    const edr::CorrelationAnnotation r2 = engine.Observe(critical);
    /* critical(90) + one extra tactic (5) = 95. */
    CE_CHECK(r2.score == 95);

    const std::vector<edr::Incident> incidents = engine.Snapshot(10);
    CE_CHECK(incidents.size() == 1);
    CE_CHECK(incidents[0].severity == "critical");
    CE_CHECK(incidents[0].alertCount == 2);
}

/* The breadth bonus is capped at 20, so a very wide chain still tops out at
 * 100 exactly when combined with a critical severity. */
void TestBreadthBonusCapped() {
    std::fprintf(stderr, "[correlation] TestBreadthBonusCapped\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2);

    const char* const tactics[] = {
        "Execution", "Persistence", "Defense Evasion",
        "Privilege Escalation", "Credential Access", "Lateral Movement"
    };
    edr::CorrelationAnnotation last;
    for (int i = 0; i < 6; ++i) {
        edr::Event ev = Event(kPid, (100 + i) * kSecond);
        edr::Alert alert = Alert(&ev, "EDR-05" + std::to_string(i), "critical",
                                 {tactics[i]});
        last = engine.Observe(alert);
    }
    /* critical(90) + 5 extra tactics, capped at +20 = 100. */
    CE_CHECK(last.score == 100);
    CE_CHECK(last.stageCount == 6);
}

/* A repeated tactic must not inflate the stage count or the score. */
void TestRepeatedTacticNoInflation() {
    std::fprintf(stderr, "[correlation] TestRepeatedTacticNoInflation\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2);

    edr::CorrelationAnnotation last;
    for (int i = 0; i < 5; ++i) {
        edr::Event ev = Event(kPid, (100 + i) * kSecond);
        edr::Alert alert = Alert(&ev, "EDR-060", "high", {"Execution"});
        last = engine.Observe(alert);
    }
    CE_CHECK(last.stageCount == 1);
    CE_CHECK(last.alertCount == 5);
    CE_CHECK(last.score == 75);
}

/* Expired incidents are flushed to the callback once they pass the window,
 * and only when they reached the minimum alert count. */
void TestFlushExpiredInvokesCallback() {
    std::fprintf(stderr, "[correlation] TestFlushExpiredInvokesCallback\n");
    edr::CorrelationEngine engine(true, 60, 256, 2);
    std::vector<std::string> emitted;
    engine.SetIncidentCallback([&](const edr::Incident& incident) {
        emitted.push_back(incident.id);
    });

    edr::Event first = Event(kPid, 100 * kSecond);
    edr::Alert a1 = Alert(&first, "EDR-070", "high", {"Execution"});
    const edr::CorrelationAnnotation r1 = engine.Observe(a1);
    edr::Event second = Event(kPid, 101 * kSecond);
    edr::Alert a2 = Alert(&second, "EDR-071", "high", {"Persistence"});
    engine.Observe(a2);
    CE_CHECK(emitted.empty());

    /* Still inside the 60s window. */
    engine.FlushExpired(150 * kSecond);
    CE_CHECK(emitted.empty());

    /* Past the window: the incident closes and is reported once. */
    engine.FlushExpired(200 * kSecond);
    CE_CHECK(emitted.size() == 1);
    CE_CHECK(emitted[0] == r1.incidentId);
    CE_CHECK(engine.IncidentCount() == 0);
}

/* A single-alert incident below the minimum is not reported on expiry: it is
 * indistinguishable from routine noise. */
void TestMinAlertsGateOnClose() {
    std::fprintf(stderr, "[correlation] TestMinAlertsGateOnClose\n");
    edr::CorrelationEngine engine(true, 60, 256, 3);
    std::vector<std::string> emitted;
    engine.SetIncidentCallback([&](const edr::Incident& incident) {
        emitted.push_back(incident.id);
    });

    edr::Event first = Event(kPid, 100 * kSecond);
    edr::Alert a1 = Alert(&first, "EDR-080", "high", {"Execution"});
    engine.Observe(a1);

    engine.FlushExpired(200 * kSecond);
    CE_CHECK(emitted.empty());
    CE_CHECK(engine.IncidentCount() == 0);
}

/* Snapshot is ordered newest-first so an operator view shows the live
 * incidents at the top. */
void TestSnapshotOrdering() {
    std::fprintf(stderr, "[correlation] TestSnapshotOrdering\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2);

    edr::Event older = Event(9401, 100 * kSecond);
    older.fields[edr::field::kImage] = "C:\\Temp\\old.exe";
    edr::Alert a1 = Alert(&older, "EDR-090", "high", {"Execution"});
    engine.Observe(a1);

    edr::Event newer = Event(9402, 300 * kSecond);
    newer.fields[edr::field::kImage] = "C:\\Temp\\new.exe";
    edr::Alert a2 = Alert(&newer, "EDR-091", "high", {"Execution"});
    engine.Observe(a2);

    const std::vector<edr::Incident> incidents = engine.Snapshot(10);
    CE_CHECK(incidents.size() == 2);
    CE_CHECK(incidents[0].primaryImage == "new.exe");
    CE_CHECK(incidents[1].primaryImage == "old.exe");
}

/* Incident state is bounded by capacity. */
void TestStateCapacityBounded() {
    std::fprintf(stderr, "[correlation] TestStateCapacityBounded\n");
    edr::CorrelationEngine engine(true, 1800, 4, 2);
    for (uint32_t i = 0; i < 64; ++i) {
        edr::Event ev = Event(9500 + i, (100 + i) * kSecond);
        ev.fields[edr::field::kImage] =
            "C:\\Temp\\img" + std::to_string(i) + ".exe";
        edr::Alert alert = Alert(&ev, "EDR-100", "high", {"Execution"});
        engine.Observe(alert);
    }
    CE_CHECK(engine.IncidentCount() <= 4);
}

/* A disabled engine never annotates. */
void TestDisabledEngineInert() {
    std::fprintf(stderr, "[correlation] TestDisabledEngineInert\n");
    edr::CorrelationEngine engine(false, 1800, 256, 2);
    edr::Event ev = Event(kPid, 100 * kSecond);
    edr::Alert alert = Alert(&ev, "EDR-110", "high", {"Execution"});
    const edr::CorrelationAnnotation annotation = engine.Observe(alert);
    CE_CHECK(annotation.incidentId.empty());
    CE_CHECK(engine.IncidentCount() == 0);
}

/* An incident serializes to valid JSON containing the kill-chain stages. */
void TestIncidentJsonShape() {
    std::fprintf(stderr, "[correlation] TestIncidentJsonShape\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2);

    edr::Event first = Event(kPid, 100 * kSecond);
    edr::Alert a1 = Alert(&first, "EDR-120", "high", {"Execution"});
    engine.Observe(a1);
    edr::Event second = Event(kPid, 101 * kSecond);
    edr::Alert a2 = Alert(&second, "EDR-121", "critical",
                          {"Credential Access"});
    engine.Observe(a2);

    const std::vector<edr::Incident> incidents = engine.Snapshot(1);
    CE_CHECK(incidents.size() == 1);
    const std::string json = edr::IncidentToJson(incidents[0]);
    CE_CHECK(json.find("\"id\":\"inc-") != std::string::npos);
    CE_CHECK(json.find("\"stages\":[") != std::string::npos);
    CE_CHECK(json.find("\"tactic\":\"Execution\"") != std::string::npos);
    CE_CHECK(json.find("\"tactic\":\"Credential Access\"") !=
             std::string::npos);
    CE_CHECK(json.find("\"alertCount\":2") != std::string::npos);
    CE_CHECK(json.find("\"image\":\"dropper.exe\"") != std::string::npos);
    CE_CHECK(json.back() == '}');
}

/* An alert that bridges two live incidents must MERGE them into one chain
 * instead of joining only the first and orphaning the second.
 *
 * This is the regression guard for the "first match wins" bug: with the old
 * single-pass lookup the bridging alert adopted the first chain and merely
 * re-pointed the second chain's entity at it, so IncidentCount stayed at 2
 * and the kill chain fragmented into two weaker pieces. */
void TestBridgingAlertMergesIncidents() {
    std::fprintf(stderr, "[correlation] TestBridgingAlertMergesIncidents\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2);

    /* Chain X: pid 9401 / a.exe / Execution. */
    edr::Event first = Event(9401, 100 * kSecond);
    first.fields[edr::field::kImage] = "C:\\Temp\\a.exe";
    first.fields[edr::field::kEndpointId] = "endpoint-local";
    edr::Alert a1 = Alert(&first, "EDR-050", "high", {"Execution"});
    const edr::CorrelationAnnotation r1 = engine.Observe(a1);
    CE_CHECK(engine.IncidentCount() == 1);

    /* Chain Y: pid 9402 / b.exe / Persistence - shares no entity with X. */
    edr::Event second = Event(9402, 101 * kSecond);
    second.fields[edr::field::kImage] = "C:\\Temp\\b.exe";
    second.fields[edr::field::kEndpointId] = "endpoint-local";
    second.fields[edr::field::kFilePath] = "C:\\Temp\\shared-artifact.bin";
    edr::Alert a2 = Alert(&second, "EDR-051", "medium", {"Persistence"});
    const edr::CorrelationAnnotation r2 = engine.Observe(a2);
    CE_CHECK(r2.incidentId != r1.incidentId);
    CE_CHECK(engine.IncidentCount() == 2);

    /* Bridging alert: carries X's process identity AND Y's image. */
    edr::Event bridge = Event(9401, 102 * kSecond);
    bridge.fields[edr::field::kImage] = "C:\\Temp\\b.exe";
    bridge.fields[edr::field::kEndpointId] = "endpoint-local";
    bridge.fields[edr::field::kFilePath] = "C:\\Temp\\shared-artifact.bin";
    edr::Alert a3 = Alert(&bridge, "EDR-052", "critical", {"Lateral Movement"});
    const edr::CorrelationAnnotation r3 = engine.Observe(a3);

    /* X and Y are now one incident, and it keeps the older id. */
    CE_CHECK(engine.IncidentCount() == 1);
    CE_CHECK(r3.incidentId == r1.incidentId);
    CE_CHECK(r3.incidentId != r2.incidentId);
    CE_CHECK(r3.alertCount == 3);
    CE_CHECK(r3.stageCount == 3);

    const std::vector<edr::Incident> snap = engine.Snapshot(8);
    CE_CHECK(snap.size() == 1);
    const edr::Incident& merged = snap.front();
    /* Nothing from the absorbed chain is lost. */
    CE_CHECK(merged.alertCount == 3);
    CE_CHECK(merged.rules.size() == 3);
    CE_CHECK(merged.tactics.size() == 3);
    CE_CHECK(merged.stages.size() == 3);
    /* Stages stay in first-sighting order across the merge. */
    CE_CHECK(merged.stages[0].tactic == "Execution");
    CE_CHECK(merged.stages[1].tactic == "Persistence");
    CE_CHECK(merged.stages[2].tactic == "Lateral Movement");
    /* The absorbed chain's rule evidence survives. */
    bool sawAbsorbedRule = false;
    for (const std::string& rule : merged.rules) {
        if (rule == "EDR-051") sawAbsorbedRule = true;
    }
    CE_CHECK(sawAbsorbedRule);
    /* Severity escalates and breadth is recomputed over the union. */
    CE_CHECK(merged.severity == "critical");
    CE_CHECK(merged.score == 100);
}

/* Merging must not duplicate a tactic both chains already recorded: it stays
 * a single graph node with the combined alert count. */
void TestMergeCoalescesSharedTactic() {
    std::fprintf(stderr, "[correlation] TestMergeCoalescesSharedTactic\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2);

    edr::Event first = Event(9405, 100 * kSecond);
    first.fields[edr::field::kImage] = "C:\\Temp\\c.exe";
    first.fields[edr::field::kEndpointId] = "endpoint-local";
    engine.Observe(Alert(&first, "EDR-060", "high", {"Discovery"}));

    edr::Event second = Event(9406, 101 * kSecond);
    second.fields[edr::field::kImage] = "C:\\Temp\\d.exe";
    second.fields[edr::field::kEndpointId] = "endpoint-local";
    second.fields[edr::field::kFilePath] = "C:\\Temp\\shared-merge.bin";
    engine.Observe(Alert(&second, "EDR-061", "high", {"Discovery"}));

    /* Bridge carrying both pids' evidence - both chains are "Discovery". */
    edr::Event bridge = Event(9405, 102 * kSecond);
    bridge.fields[edr::field::kImage] = "C:\\Temp\\d.exe";
    bridge.fields[edr::field::kEndpointId] = "endpoint-local";
    bridge.fields[edr::field::kFilePath] = "C:\\Temp\\shared-merge.bin";
    engine.Observe(Alert(&bridge, "EDR-062", "high", {"Discovery"}));

    CE_CHECK(engine.IncidentCount() == 1);
    const std::vector<edr::Incident> snap = engine.Snapshot(8);
    CE_CHECK(snap.size() == 1);
    /* One tactic, one stage - but all three alerts counted on it. */
    CE_CHECK(snap.front().tactics.size() == 1);
    CE_CHECK(snap.front().stages.size() == 1);
    CE_CHECK(snap.front().stages.front().alertCount == 3);
    CE_CHECK(snap.front().stages.front().firstSeen100ns == 100 * kSecond);
    CE_CHECK(snap.front().stages.front().lastSeen100ns == 102 * kSecond);
    /* Single tactic => no breadth bonus, just the high severity weight. */
    CE_CHECK(snap.front().score == 75);
}

/* The absorbed incident must be announced (its roll-up would otherwise
 * disappear silently), and entities must all resolve to the survivor. */
void TestMergeAnnouncesAbsorbedIncident() {
    std::fprintf(stderr, "[correlation] TestMergeAnnouncesAbsorbedIncident\n");
    edr::CorrelationEngine engine(true, 1800, 256, 2);

    std::vector<std::string> emitted;
    engine.SetIncidentCallback(
        [&emitted](const edr::Incident& incident) {
            emitted.push_back(incident.id);
        });

    edr::Event first = Event(9411, 100 * kSecond);
    first.fields[edr::field::kImage] = "C:\\Temp\\e.exe";
    first.fields[edr::field::kEndpointId] = "endpoint-local";
    const edr::CorrelationAnnotation r1 =
        engine.Observe(Alert(&first, "EDR-070", "high", {"Execution"}));

    edr::Event second = Event(9412, 101 * kSecond);
    second.fields[edr::field::kImage] = "C:\\Temp\\f.exe";
    second.fields[edr::field::kEndpointId] = "endpoint-local";
    second.fields[edr::field::kFilePath] = "C:\\Temp\\shared-announcement.bin";
    const edr::CorrelationAnnotation r2 =
        engine.Observe(Alert(&second, "EDR-071", "high", {"Persistence"}));

    edr::Event bridge = Event(9411, 102 * kSecond);
    bridge.fields[edr::field::kImage] = "C:\\Temp\\f.exe";
    bridge.fields[edr::field::kEndpointId] = "endpoint-local";
    bridge.fields[edr::field::kFilePath] = "C:\\Temp\\shared-announcement.bin";
    engine.Observe(Alert(&bridge, "EDR-072", "high", {"Lateral Movement"}));

    /* The survivor was announced once, carrying the absorbed alert count. */
    bool announcedSurvivor = false;
    for (const std::string& id : emitted) {
        if (id == r1.incidentId) announcedSurvivor = true;
    }
    CE_CHECK(announcedSurvivor);
    CE_CHECK(engine.IncidentCount() == 1);

    /* A brand-new alert on the absorbed chain's old pivot still lands on the
     * survivor - proving the entity table was re-pointed, not orphaned. */
    edr::Event after = Event(9412, 103 * kSecond);
    after.fields[edr::field::kImage] = "C:\\Temp\\g.exe";
    after.processStartTime100ns = second.processStartTime100ns;
    after.fields[edr::field::kEndpointId] = "endpoint-local";
    const edr::CorrelationAnnotation r4 =
        engine.Observe(Alert(&after, "EDR-073", "high", {"Collection"}));
    CE_CHECK(r4.incidentId == r1.incidentId);
    CE_CHECK(r4.incidentId != r2.incidentId);
    CE_CHECK(engine.IncidentCount() == 1);
    CE_CHECK(r4.alertCount == 4);
}

} // namespace

void RunCorrelationEngineTests() {
    TestIncidentIdsRemainDistinctAcrossEngineRestart();
    TestRunIdFactoryFailure();
    TestSameProcessFolds();
    TestImageBasenameDoesNotFold();
    TestBarePidDoesNotCorrelateAndProcessReuseStaysSeparate();
    TestEndpointScopesStrongAndWeakEntities();
    TestSysmonAndEtwExactInstanceIdentityCorrelates();
    TestOpaqueIdentityDoesNotCrossProducerBoundary();
    TestProcessAliasesJoinPartialAndParentEvidence();
    TestProcessAliasScopeConflictAndWeakIdentity();
    TestProcessAliasCapacityExpiryAndLateEvents();
    TestAliasPromotesAndMergesExistingExactIncident();
    TestStrongAliasesRemainIndependentAcrossScopes();
    TestLateEvidenceDoesNotRegressIncidentOrAliasTime();
    TestConflictedAliasRemainsBlockedAfterExpiry();
    TestConflictingAliasCapacityFailsClosed();
    TestSourceIsNotEndpointIdentity();
    TestUnrelatedAlertsSeparate();
    TestUserOnlyPivotDoesNotFold();
    TestSeverityRollup();
    TestBreadthBonusCapped();
    TestRepeatedTacticNoInflation();
    TestFlushExpiredInvokesCallback();
    TestMinAlertsGateOnClose();
    TestSnapshotOrdering();
    TestStateCapacityBounded();
    TestDisabledEngineInert();
    TestIncidentJsonShape();
    TestBridgingAlertMergesIncidents();
    TestMergeCoalescesSharedTactic();
    TestMergeAnnouncesAbsorbedIncident();
    std::fprintf(stderr, "[correlation] all passed\n");
}
