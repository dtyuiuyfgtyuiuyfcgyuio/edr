#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include "collector.h"
#include "collector_local_account.h"

namespace {
using Status = edr::LocalAccountQueryStatus;
using Page = edr::LocalAccountPage;
void Require(bool condition, const char* message) {
    if (!condition) { std::fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
}
template<class F> bool Wait(F predicate) {
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    do { if (predicate()) return true; std::this_thread::sleep_for(std::chrono::milliseconds(5)); }
    while (std::chrono::steady_clock::now() < end);
    return predicate();
}
Page Users(std::initializer_list<const char*> names) {
    Page page; page.status = Status::Complete;
    for (auto name : names) page.users.push_back({name, name, true});
    return page;
}
Page Members(std::initializer_list<const char*> names) {
    Page page; page.status = Status::Complete;
    for (auto name : names) page.members.push_back({name, "HOST"});
    return page;
}
Page State(Status state) { Page p; p.status = state; return p; }
using Pages = std::map<std::string, std::vector<Page>>;
class Script {
public:
    void Set(Pages pages) {
        std::lock_guard<std::mutex> lock(mutex);
        desired = std::move(pages); ++revision;
    }
    edr::LocalAccountQuery Callback() {
        return [this](const std::string& group, uint64_t resume) {
            std::lock_guard<std::mutex> lock(mutex);
            if (group.empty() && resume == 0) {
                // Beginning the following poll proves the preceding one finished.
                finishedRevision = activeRevision;
                current = desired; activeRevision = revision;
            }
            auto it = current.find(group);
            if (it == current.end()) return State(Status::Complete);
            if (resume >= it->second.size()) return State(Status::Failed);
            return it->second[static_cast<size_t>(resume)];
        };
    }
    void Applied() {
        Require(Wait([&] {
            std::lock_guard<std::mutex> lock(mutex);
            return finishedRevision >= revision;
        }), "script round is fully processed");
    }
private:
    std::mutex mutex;
    Pages desired, current;
    uint64_t revision = 0, activeRevision = 0, finishedRevision = 0;
};
class Fixture {
public:
    explicit Fixture(Script& script, size_t capacity = 1024,
                     std::vector<std::string> groups = {"Admins", "Remote"})
        : bus(capacity), collector(edr::CreateLocalAccountCollector(10, groups, script.Callback())) {
        Require(collector->GetHealthSnapshot().supported, "local account health supported before start");
        Require(!collector->Start(nullptr), "null bus rejected");
        Require(collector->Start(&bus), "worker starts");
        Require(collector->Start(&bus), "start is idempotent for active worker");
        script.Applied();
    }
    ~Fixture() { collector->Stop(); }
    edr::CollectorHealthSnapshot Health() { return collector->GetHealthSnapshot(); }
    void NoEvents() { Require(Health().eventsPushed == 0, "no invented account/group changes"); }
    edr::EventBus bus;
    std::unique_ptr<edr::ICollector> collector;
};
class Recorder : public edr::ISink {
public:
    void OnEvent(const edr::Event& event) override {
        std::lock_guard<std::mutex> lock(mutex); events.push_back(event);
    }
    std::vector<edr::Event> Read() { std::lock_guard<std::mutex> lock(mutex); return events; }
private:
    std::mutex mutex;
    std::vector<edr::Event> events;
};

void FailurePreservesBaselineAndIndependentDomains() {
    Script script;
    script.Set({{"", {Users({"alice"})}}, {"Admins", {Members({"alice"})}}});
    Fixture f(script); f.NoEvents();
    script.Set({{"", {State(Status::Failed)}}, {"Admins", {Members({"alice", "bob"})}}});
    script.Applied();
    auto h = f.Health();
    Require(h.eventsPushed == 1, "group change survives unrelated user failure");
    Require(h.state == "source_error", "group success cannot hide user failure");
    Require(h.counters.at("failed_domains") == 1, "current failure coverage exposed");
    script.Set({{"", {Users({"alice"})}}, {"Admins", {Members({"alice", "bob"})}}});
    script.Applied();
    Require(f.Health().eventsPushed == 1, "failure then same complete users has no remove/add");
    Require(f.Health().state == "running", "all domains recover");
    script.Set({{"", {Users({})}}, {"Admins", {Members({"alice", "bob"})}}});
    script.Applied();
    Require(f.Health().eventsPushed == 2, "complete empty user domain emits deletion");
    f.collector->Stop();
    Recorder recorder; f.bus.Start(&recorder);
    Require(Wait([&] { return recorder.Read().size() == 2; }), "both actual events delivered");
    f.bus.Stop();
    const auto events = recorder.Read();
    Require(events[0].fields.at(edr::field::kAccountType) == "group" &&
            events[0].fields.at(edr::field::kGroupAction) == "added" &&
            events[0].fields.at(edr::field::kGroupName) == "Admins" &&
            events[0].fields.at(edr::field::kGroupMember) == "bob" &&
            events[0].fields.at(edr::field::kGroupMemberDomain) == "HOST",
            "genuine independent group addition preserves existing event fields");
    Require(events[1].fields.at(edr::field::kAccountAction) == "removed" &&
            events[1].fields.at(edr::field::kAccountName) == "alice" &&
            events[1].fields.at(edr::field::kAccountFullName) == "alice" &&
            events[1].fields.at(edr::field::kAccountEnabled) == "true" &&
            events[1].source == "local_account_monitor" && events[1].ts100ns != 0,
            "genuine user deletion preserves existing event fields and timestamp");
}
void FirstFailureSeedsAndMissingRecovers() {
    Script script;
    script.Set({{"", {State(Status::Failed)}}, {"Admins", {State(Status::Missing)}}});
    Fixture f(script); f.NoEvents();
    script.Set({{"", {Users({"alice"})}}, {"Admins", {State(Status::Missing)}}});
    script.Applied(); f.NoEvents();
    Require(f.Health().state == "coverage_degraded", "missing configured group degrades coverage");
    Require(f.Health().counters.at("missing_groups") == 1, "missing group count exposed");
    script.Set({{"", {Users({"alice"})}}, {"Admins", {Members({"alice"})}}});
    script.Applied(); f.NoEvents();
    Require(f.Health().state == "running", "missing group retried and recovered");
    script.Set({{"", {Users({"alice"})}}, {"Admins", {State(Status::Missing)}}});
    script.Applied(); f.NoEvents();
    script.Set({{"", {Users({"alice"})}}, {"Admins", {Members({"alice"})}}});
    script.Applied(); f.NoEvents();
    script.Set({{"", {Users({"alice"})}}, {"Admins", {Members({})}}});
    script.Applied();
    Require(f.Health().eventsPushed == 1, "complete empty group emits removal");
}
void PartialPagesNeverPublishAndResumeIsBounded() {
    Script script; script.Set({{"", {Users({"alice"})}}}); Fixture f(script);
    Page first = Users({"bob"}); first.status = Status::MoreData; first.resumeHandle = 1;
    script.Set({{"", {first, State(Status::Failed)}}}); script.Applied(); f.NoEvents();
    Require(f.Health().state == "source_error", "later page failure marks entire domain failed");
    script.Set({{"", {Users({"alice"})}}}); script.Applied(); f.NoEvents();
    Page second = Users({"alice"});
    script.Set({{"", {first, second}}}); script.Applied();
    Require(f.Health().eventsPushed == 1, "complete multi-page user snapshot publishes once");
    first.resumeHandle = 0;
    script.Set({{"", {first}}}); script.Applied();
    Require(f.Health().state == "source_error", "nonadvancing resume fails boundedly");
    Require(f.Health().eventsPushed == 1, "nonadvancing partial page does not replace baseline");
    first.resumeHandle = 1;
    second.status = Status::MoreData; second.resumeHandle = 2;
    Page third = Users({"charlie"}); third.status = Status::MoreData; third.resumeHandle = 1;
    script.Set({{"", {first, second, third}}}); script.Applied();
    Require(f.Health().eventsPushed == 1, "cycling resume does not publish");
    Page groupFirst = Members({"bob"}); groupFirst.status = Status::MoreData; groupFirst.resumeHandle = 1;
    script.Set({{"", {Users({"alice", "bob"})}}, {"Admins", {groupFirst, State(Status::Failed)}}});
    script.Applied();
    Require(f.Health().eventsPushed == 1, "partial group candidate never publishes");
}
void InvalidAndCapacityCandidatesPreserveBaseline() {
    Script script; script.Set({{"", {Users({"alice"})}}}); Fixture f(script);
    std::vector<Page> invalid;
    invalid.push_back(Users({"bob", "bob"}));
    invalid.push_back(Users({""}));
    Page malformed = Users({"bob"}); malformed.users[0].name = std::string("bo\0b", 4); invalid.push_back(malformed);
    malformed = Users({"bob"}); malformed.users[0].fullName = std::string("\xc3\x28", 2); invalid.push_back(malformed);
    invalid.push_back(State(Status::Missing)); // Missing cannot mean no local users.
    invalid.push_back(Members({"bob"})); // A user domain cannot contain membership entries.
    Page huge = Users({"bob"}); huge.users[0].fullName.assign(4097, 'x'); invalid.push_back(huge);
    huge = Users({}); for (size_t i = 0; i < 16385; ++i) huge.users.push_back({std::to_string(i), "", true});
    invalid.push_back(std::move(huge));
    huge = Users({}); for (size_t i = 0; i < 1100; ++i) huge.users.push_back({std::to_string(i), std::string(4096, 'x'), true});
    invalid.push_back(std::move(huge));
    for (auto& page : invalid) {
        script.Set({{"", {page}}}); script.Applied(); f.NoEvents();
        Require(f.Health().state == "source_error", "invalid/overbudget full candidate rejected");
    }
    script.Set({{"", {Users({"alice"})}}}); script.Applied(); f.NoEvents();
    Require(f.Health().counters.at("capacity_rejections") >= 3, "capacity failures observable");
}
void CompleteGroupPagesAndFailedEmptyPage() {
    Script script; script.Set({}); Fixture f(script);
    Page first = Members({"alice"}); first.status = Status::MoreData; first.resumeHandle = 1;
    script.Set({{"Admins", {first, Members({"bob"})}}}); script.Applied();
    Require(f.Health().eventsPushed == 2 && f.Health().state == "running",
            "complete multipage group emits all additions");
    Page empty = Members({}); empty.status = Status::MoreData; empty.resumeHandle = 1;
    script.Set({{"Admins", {empty, Members({})}}}); script.Applied();
    Require(f.Health().eventsPushed == 2 && f.Health().state == "source_error",
            "empty nonterminal page cannot certify complete group or emit removals");
    script.Set({{"Admins", {first, State(Status::Missing)}}}); script.Applied();
    Require(f.Health().eventsPushed == 2 && f.Health().counters.at("failed_domains") == 1,
            "group disappearing mid-pagination is failed rather than authoritative missing");
}
void PageBudgetAndRetainedBudget() {
    Script script; script.Set({}); Fixture f(script);
    std::vector<Page> pages;
    for (size_t i = 0; i < 257; ++i) {
        Page p = Users({}); p.users.push_back({std::to_string(i), "", true});
        p.status = Status::MoreData; p.resumeHandle = i + 1; pages.push_back(std::move(p));
    }
    script.Set({{"", pages}}); script.Applied(); f.NoEvents();
    Require(f.Health().state == "source_error", "page budget fails without publishing");
    std::vector<std::string> groups = {"A", "B", "C", "D", "E", "F"};
    Pages big;
    for (const auto& group : groups) {
        Page p = Members({});
        for (size_t i = 0; i < 420; ++i) p.members.push_back({std::to_string(i), std::string(4096, 'd')});
        big[group] = {std::move(p)};
    }
    Script large; large.Set(std::move(big)); Fixture budget(large, 8, groups);
    Require(budget.Health().state == "source_error", "aggregate retained budget enforced across domains");
    Require(budget.Health().counters.at("successful_domains") == 5 &&
            budget.Health().counters.at("failed_domains") == 2,
            "four groups fit individually and collectively; fifth/sixth exceed retained budget");
    Require(budget.Health().counters.at("retained_bytes") <= 16 * 1024 * 1024, "retained charge remains bounded");
}
void GroupFailurePersistsAcrossSuccessAndModificationContract() {
    Script script;
    script.Set({{"", {Users({"alice"})}}, {"Admins", {Members({"alice"})}}, {"Remote", {Members({"alice"})}}});
    Fixture f(script);
    Page changed = Users({"alice"}); changed.users[0].fullName = "Alice Example"; changed.users[0].enabled = false;
    script.Set({{"", {changed}}, {"Admins", {State(Status::Failed)}}, {"Remote", {Members({"alice"})}}});
    script.Applied();
    Require(f.Health().state == "source_error" && f.Health().eventsPushed == 1,
            "user modification and later successful group never hide failed group");
    script.Set({{"", {changed}}, {"Admins", {Members({"alice"})}}, {"Remote", {Members({"alice"})}}});
    script.Applied();
    Require(f.Health().eventsPushed == 1, "group failure and same recovery produces no membership churn");
    f.collector->Stop();
    Recorder recorder; f.bus.Start(&recorder);
    Require(Wait([&] { return recorder.Read().size() == 1; }), "modification delivered");
    f.bus.Stop();
    const auto event = recorder.Read().front();
    Require(event.fields.at(edr::field::kAccountAction) == "modified" &&
            event.fields.at(edr::field::kAccountFullName) == "Alice Example" &&
            event.fields.at(edr::field::kAccountEnabled) == "false",
            "full name and enabled changes retain modification contract");
}
void ConfigurationAndWorkerHealth() {
    edr::EventBus bus(1);
    std::unique_ptr<edr::ICollector> configured(edr::CreateLocalAccountCollector(1, {"Admins"}));
    Require(configured->GetHealthSnapshot().counters.at("retained_bytes") > 0,
            "configuration storage is charged before collecting a baseline");
    std::unique_ptr<edr::ICollector> bad(edr::CreateLocalAccountCollector(1, std::vector<std::string>(33, "Admins")));
    Require(!bad->Start(&bus), "excessive configured group count rejected");
    Require(bad->GetHealthSnapshot().state == "config_error", "configuration failure observable");
    bad.reset(edr::CreateLocalAccountCollector(1, {std::string(1025, 'x')}));
    Require(!bad->Start(&bus), "oversized group name rejected");
    bad.reset(edr::CreateLocalAccountCollector(1, {std::string("\xc3\x28", 2)}));
    Require(!bad->Start(&bus), "invalid UTF-8 configured group rejected");
    bad.reset(edr::CreateLocalAccountCollector(1, {""}));
    Require(!bad->Start(&bus), "empty configured group cannot alias user domain");
    std::atomic<unsigned> calls{0};
    std::unique_ptr<edr::ICollector> fatal(edr::CreateLocalAccountCollector(1, {"Admins"},
        [&](const std::string&, uint64_t) -> Page { ++calls; throw std::runtime_error("injected"); }));
    Require(fatal->Start(&bus), "exception worker starts");
    Require(Wait([&] { auto h = fatal->GetHealthSnapshot(); return calls != 0 && !h.running && h.state == "source_error"; }), "worker exception caught and health stopped with error");
    Require(!fatal->Start(&bus), "dead joinable worker cannot claim successful start");
    fatal->Stop();
    Require(fatal->GetHealthSnapshot().state == "stopped", "explicit stop joins failed worker");
    Script script; script.Set({}); Fixture f(script, 1);
    script.Set({{"", {Users({"alice", "bob"})}}}); script.Applied();
    Require(f.Health().eventsPushed == 2 && f.Health().busDropped == 1, "overflow counts current event submission and old eviction separately");
    f.collector->Stop(); f.collector->Stop();
    Require(!f.Health().running && f.Health().state == "stopped", "stop is idempotent");
    Require(f.collector->Start(&f.bus), "stopped collector restarts");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    Require(f.Health().eventsPushed == 2, "restart seeds baseline without duplicate additions");
    std::unique_ptr<edr::ICollector> slow(edr::CreateLocalAccountCollector(UINT32_MAX, {"Admins"},
        [](const std::string&, uint64_t) { return State(Status::Complete); }));
    Require(slow->Start(&bus), "long interval worker starts");
    Require(Wait([&] { return slow->GetHealthSnapshot().state == "running"; }), "long interval baseline completes");
    const auto beforeStop = std::chrono::steady_clock::now();
    slow->Stop();
    Require(std::chrono::steady_clock::now() - beforeStop < std::chrono::seconds(1),
            "stop wakes long polling delay promptly without uint32 overflow");
}
}
int main() {
    FailurePreservesBaselineAndIndependentDomains();
    FirstFailureSeedsAndMissingRecovers();
    PartialPagesNeverPublishAndResumeIsBounded();
    CompleteGroupPagesAndFailedEmptyPage();
    InvalidAndCapacityCandidatesPreserveBaseline();
    PageBudgetAndRetainedBudget();
    GroupFailurePersistsAcrossSuccessAndModificationContract();
    ConfigurationAndWorkerHealth();
    std::puts("local account collector tests passed");
}
