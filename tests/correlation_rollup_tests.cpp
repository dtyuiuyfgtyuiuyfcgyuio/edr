#include "correlation_rollup_tests.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "correlation_rollup.h"
#include "edr_event.h"
#include "event_bus.h"
#include "rule_engine.h"

namespace {

using namespace edr;

#define CR_CHECK(value) Check((value), #value, __LINE__)

void Check(bool value, const char* expression, int line) {
    if (!value) throw std::runtime_error("correlation rollup test failed at line " +
        std::to_string(line) + ": " + expression);
}

/* Captures whatever the roll-up pushes onto a live bus. */
class RecordingSink : public ISink {
public:
    void OnEvent(const Event& ev) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_events.push_back(ev);
    }

    /* The consumer thread is asynchronous; wait for the expected count rather
     * than assuming the push already landed. */
    bool WaitFor(size_t expected, int timeoutMs = 2000) {
        for (int i = 0; i < timeoutMs; i += 10) {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_events.size() >= expected) return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return false;
    }

    std::vector<Event> Copy() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_events;
    }

    size_t Count() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_events.size();
    }

private:
    mutable std::mutex m_mutex;
    std::vector<Event> m_events;
};

CorrelationAnnotation Making(uint32_t stageCount, int score) {
    CorrelationAnnotation annotation;
    annotation.incidentId = "inc-run-1";
    annotation.stage = "Execution";
    annotation.tactics = "Execution,Credential Access,Lateral Movement,Collection";
    annotation.score = score;
    annotation.alertCount = stageCount * 2;
    annotation.stageCount = stageCount;
    return annotation;
}

/* The alert that produced the roll-up. Only its clock and endpoint are
 * inherited by the published event. */
Event Origin() {
    Event event;
    event.type = EDR_EVT_FILE_CREATE;
    event.source = "sysmon";
    event.ts100ns = 1'325'000'000'000ULL;
    event.pid = 4711;
    event.processIdentity = "C:\\temp\\evil.exe";
    event.fields[field::kEndpointId] = "HOST-A";
    event.fields[field::kTimestampProvenance] = "collector";
    return event;
}

std::string FieldOf(const Event& event, const char* name) {
    auto found = event.fields.find(name);
    return found == event.fields.end() ? std::string() : found->second;
}

void TestCampaignBandPublishes() {
    EventBus bus;
    RecordingSink sink;
    bus.Start(&sink);
    CorrelationRollup rollup(true, 4, 85, 16);
    rollup.SetBus(&bus);

    CR_CHECK(rollup.Publish(Making(4, 90), Origin()));
    CR_CHECK(sink.WaitFor(1));
    const Event published = sink.Copy().front();
    CR_CHECK(published.type == EDR_EVT_INCIDENT_CORRELATED);
    CR_CHECK(FieldOf(published, field::kType) == "INCIDENT_CORRELATED");
    CR_CHECK(published.source == "correlation");
    CR_CHECK(FieldOf(published, field::kSource) == "correlation");
    CR_CHECK(FieldOf(published, field::kCorrelatedIncidentId) == "inc-run-1");
    CR_CHECK(FieldOf(published, field::kCorrelatedStage) == "Execution");
    CR_CHECK(FieldOf(published, field::kCorrelatedScore) == "90");
    CR_CHECK(FieldOf(published, field::kCorrelatedStageCount) == "4");
    CR_CHECK(FieldOf(published, field::kCorrelatedAlertCount) == "8");
    CR_CHECK(published.ts100ns == 1'325'000'000'000ULL);
    /* The roll-up must not impersonate a collected process: no identity may
     * be copied from the origin, or the correlator could pivot on it. */
    CR_CHECK(published.pid == 0);
    CR_CHECK(published.processIdentity.empty());
    CR_CHECK(FieldOf(published, field::kEndpointId) == "HOST-A");
    bus.Stop();
}

void TestBelowBandIsSilent() {
    EventBus bus;
    RecordingSink sink;
    bus.Start(&sink);
    CorrelationRollup rollup(true, 4, 85, 16);
    rollup.SetBus(&bus);

    CR_CHECK(!rollup.Publish(Making(3, 95), Origin()));   /* too few tactics */
    CR_CHECK(!rollup.Publish(Making(6, 80), Origin()));   /* score below gate */
    CR_CHECK(sink.Count() == 0);
    CR_CHECK(rollup.PublishedCount() == 0);
    bus.Stop();
}

void TestOnlyGrowthReAnnounces() {
    EventBus bus;
    RecordingSink sink;
    bus.Start(&sink);
    CorrelationRollup rollup(true, 4, 85, 16);
    rollup.SetBus(&bus);

    CR_CHECK(rollup.Publish(Making(4, 90), Origin()));
    /* Same campaign shape: more alerts on the same tactics is not news. */
    CR_CHECK(!rollup.Publish(Making(4, 92), Origin()));
    CR_CHECK(!rollup.Publish(Making(4, 90), Origin()));
    /* A further distinct tactic, or a 10-point higher score, is. */
    CR_CHECK(rollup.Publish(Making(5, 90), Origin()));
    CR_CHECK(rollup.Publish(Making(5, 100), Origin()));
    CR_CHECK(sink.WaitFor(3));
    CR_CHECK(sink.Count() == 3);
    const std::vector<Event> events = sink.Copy();
    CR_CHECK(FieldOf(events[1], field::kCorrelatedStageCount) == "5");
    CR_CHECK(FieldOf(events[2], field::kCorrelatedScore) == "100");
    bus.Stop();
}

void TestDisabledPublishesNothing() {
    EventBus bus;
    RecordingSink sink;
    bus.Start(&sink);
    CorrelationRollup rollup(false, 4, 85, 16);
    rollup.SetBus(&bus);

    CR_CHECK(!rollup.Publish(Making(6, 100), Origin()));
    CR_CHECK(sink.Count() == 0);
    bus.Stop();
}

void TestOverflowDoesNotConsumeTheAnnouncement() {
    /* No sink is started, so the single-slot queue stays full and every push
     * is rejected. A rejected roll-up must not be recorded as announced, or
     * the campaign would be silently lost. */
    EventBus bus(1);
    CorrelationRollup rollup(true, 4, 85, 16);
    rollup.SetBus(&bus);

    CorrelationAnnotation first = Making(4, 90);
    first.incidentId = "inc-a";
    CR_CHECK(rollup.Publish(first, Origin()));

    CorrelationAnnotation second = Making(5, 95);
    second.incidentId = "inc-b";
    CR_CHECK(!rollup.Publish(second, Origin()));
    CR_CHECK(rollup.PublishedCount() == 1);
    CR_CHECK(bus.DroppedCount() >= 1);
    /* inc-b stayed unannounced, so it is retried on the next alert. */
    CR_CHECK(!rollup.Publish(second, Origin()));
    CR_CHECK(rollup.TrackedCount() == 1);
}

void TestRollupIdentity() {
    Event rollupEvent = Origin();
    rollupEvent.type = EDR_EVT_INCIDENT_CORRELATED;
    CR_CHECK(CorrelationRollup::IsRollup(rollupEvent));
    CR_CHECK(!CorrelationRollup::IsRollup(Origin()));
}

/* The point of the whole component: production rule EDR-443 can only fire on
 * an event this roll-up emits. Load the shipped rule set and prove both the
 * positive and the negative case. */
void TestProductionRuleEdr443IsReachable() {
    const char* candidates[] = { "..\\rules\\rules.json", "rules\\rules.json",
                                 "..\\..\\rules\\rules.json" };
    std::string path;
    for (const char* candidate : candidates) {
        std::ifstream probe(candidate);
        if (probe) { path = candidate; break; }
    }
    if (path.empty()) throw std::runtime_error("rules.json not found from the test working directory");

    RuleEngine engine;
    engine.LoadFromFile(path);
    std::vector<std::string> hits;
    engine.SetAlertCallback([&hits](const Alert& alert) { hits.push_back(alert.ruleId); });

    EventBus bus;
    RecordingSink sink;
    bus.Start(&sink);
    CorrelationRollup rollup(true, 4, 85, 16);
    rollup.SetBus(&bus);

    CR_CHECK(rollup.Publish(Making(4, 90), Origin()));
    CR_CHECK(sink.WaitFor(1));
    engine.OnEvent(sink.Copy().front());
    CR_CHECK(std::find(hits.begin(), hits.end(), "EDR-443") != hits.end());

    /* A 3-tactic chain scores below the campaign gate: nothing is emitted and
     * the rule stays quiet. */
    hits.clear();
    EventBus quietBus(1024);
    RecordingSink quietSink;
    quietBus.Start(&quietSink);
    CorrelationRollup strict(true, 4, 85, 16);
    strict.SetBus(&quietBus);
    CR_CHECK(!strict.Publish(Making(3, 90), Origin()));
    CR_CHECK(quietSink.Count() == 0);
    bus.Stop();
    quietBus.Stop();
}

} // namespace

void RunCorrelationRollupTests() {
    TestCampaignBandPublishes();
    TestBelowBandIsSilent();
    TestOnlyGrowthReAnnounces();
    TestDisabledPublishesNothing();
    TestOverflowDoesNotConsumeTheAnnouncement();
    TestRollupIdentity();
    TestProductionRuleEdr443IsReachable();
}
