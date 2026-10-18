/* rule_engine_reload_tests.cpp - content-aware rules hot-reload tests. */
#include <windows.h>

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include "rule_engine.h"

namespace {

int g_failures = 0;

#define CHECK(expression) do { \
    if (!(expression)) { \
        std::cerr << "check failed at line " << __LINE__ << ": " \
                  << #expression << "\n"; \
        ++g_failures; \
    } \
} while (0)

const char* kRulesPath = "edr-rule-engine-reload-tests.json";

std::string FindProductionRulesPath() {
    for (const char* candidate : {"rules/rules.json", "../rules/rules.json",
                                  "../../rules/rules.json"}) {
        if (GetFileAttributesA(candidate) != INVALID_FILE_ATTRIBUTES)
            return candidate;
    }
    throw std::runtime_error("production rules.json not found");
}

void WriteFile(const std::string& content) {
    std::ofstream out(kRulesPath, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot create test rules file");
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!out) throw std::runtime_error("cannot write test rules file");
}

bool LoadFails(const std::string& content) {
    WriteFile(content);
    edr::RuleEngine engine;
    try {
        engine.LoadFromFile(kRulesPath);
    } catch (const std::exception&) {
        return true;
    }
    return false;
}

FILETIME ReadWriteTime() {
    HANDLE handle = CreateFileA(kRulesPath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        throw std::runtime_error("cannot open test rules file for timestamp");
    FILETIME writeTime{};
    const BOOL ok = GetFileTime(handle, nullptr, nullptr, &writeTime);
    CloseHandle(handle);
    if (!ok) throw std::runtime_error("cannot read test rules timestamp");
    return writeTime;
}

void RestoreWriteTime(const FILETIME& writeTime) {
    HANDLE handle = CreateFileA(kRulesPath, FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        throw std::runtime_error("cannot open test rules file for timestamp");
    const BOOL ok = SetFileTime(handle, nullptr, nullptr, &writeTime);
    CloseHandle(handle);
    if (!ok) throw std::runtime_error("cannot restore test rules timestamp");
}

void WriteWithTimestamp(const std::string& content, const FILETIME& writeTime) {
    WriteFile(content);
    RestoreWriteTime(writeTime);
}

void TestSameMetadataReloadsContent() {
    const std::string first =
        R"({"rules":[{"id":"EDR-701","severity":"low","action":"alert","match":{"type":{"eq":"A"}}}]})";
    const std::string second =
        R"({"rules":[{"id":"EDR-702","severity":"low","action":"alert","match":{"type":{"eq":"B"}}}]})";
    CHECK(first.size() == second.size());

    WriteFile(first);
    const FILETIME initialWriteTime = ReadWriteTime();
    edr::RuleEngine engine;
    engine.LoadFromFile(kRulesPath);
    CHECK(engine.RuleCount() == 1);
    CHECK(engine.ReloadCount() == 0);

    WriteWithTimestamp(second, initialWriteTime);
    CHECK(engine.MaybeReload());
    CHECK(engine.ReloadCount() == 1);

    bool sawSecond = false;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        sawSecond = alert.ruleId == "EDR-702";
    });
    edr::Event event;
    event.fields["type"] = "B";
    engine.OnEvent(event);
    CHECK(sawSecond);
}

void TestInvalidContentKeepsPreviousRulesAndRetriesAfterChange() {
    const std::string valid =
        R"({"rules":[{"id":"EDR-703","severity":"low","action":"alert","match":{"type":{"eq":"C"}}}]})";
    const std::string replacement =
        R"({"rules":[{"id":"EDR-704","severity":"low","action":"alert","match":{"type":{"eq":"D"}}}]})";
    CHECK(valid.size() == replacement.size());

    WriteFile(valid);
    const FILETIME initialWriteTime = ReadWriteTime();
    edr::RuleEngine engine;
    engine.LoadFromFile(kRulesPath);
    CHECK(engine.RuleCount() == 1);

    const std::string invalid(valid.size(), 'x');
    WriteWithTimestamp(invalid, initialWriteTime);
    CHECK(!engine.MaybeReload());
    CHECK(engine.RuleCount() == 1);
    CHECK(engine.ReloadCount() == 0);

    WriteWithTimestamp(replacement, initialWriteTime);
    CHECK(engine.MaybeReload());
    CHECK(engine.ReloadCount() == 1);
    bool sawReplacement = false;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        sawReplacement = alert.ruleId == "EDR-704";
    });
    edr::Event event;
    event.fields["type"] = "D";
    engine.OnEvent(event);
    CHECK(sawReplacement);
}

void TestLintSeverityErrorsRejectInitialLoad() {
    CHECK(LoadFails(
        R"({"rules":[{"id":"EDR-705","severity":"severe","action":"alert","match":{"type":{"eq":"X"}}}]})"));
}

void TestCustomRuleIdsRemainLoadable() {
    WriteFile(
        R"({"rules":[{"id":"baseline","severity":"high","action":"alert","match":{"type":{"eq":"CUSTOM"}}}]})");
    edr::RuleEngine engine;
    engine.LoadFromFile(kRulesPath);
    CHECK(engine.RuleCount() == 1);
    bool matched = false;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        matched = alert.ruleId == "baseline";
    });
    edr::Event event;
    event.fields["type"] = "CUSTOM";
    engine.OnEvent(event);
    CHECK(matched);
}

void TestWarningsAndLegacyIdRemainLoadable() {
    WriteFile(
        R"({"rules":[{"id":"EDR-003-KILL","severity":"high","action":"alert","comments":"legacy compatibility","match":{"type":{"eq":"LEGACY"}}}]})");
    edr::RuleEngine engine;
    engine.LoadFromFile(kRulesPath);
    CHECK(engine.RuleCount() == 1);
    bool matched = false;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        matched = alert.ruleId == "EDR-003-KILL";
    });
    edr::Event event;
    event.fields["type"] = "LEGACY";
    engine.OnEvent(event);
    CHECK(matched);
}

void TestProductionRulesWithWarningsRemainLoadable() {
    edr::RuleEngine engine;
    engine.LoadFromFile(FindProductionRulesPath());
    CHECK(engine.RuleCount() >= 500);
}

void TestLintErrorReloadKeepsOldRulesAndCorrectedFileRecovers() {
    const std::string valid =
        R"({"rules":[{"id":"EDR-706","severity":"low","action":"alert","match":{"type":{"eq":"GOOD"}}}]})";
    const std::string corrected =
        R"({"rules":[{"id":"EDR-707","severity":"low","action":"alert","match":{"type":{"eq":"FINE"}}}]})";
    CHECK(valid.size() == corrected.size());
    WriteFile(valid);
    const FILETIME initialWriteTime = ReadWriteTime();
    edr::RuleEngine engine;
    engine.LoadFromFile(kRulesPath);

    std::string badSeverity = valid;
    const size_t severity = badSeverity.find("\"low\"");
    badSeverity.replace(severity, 5, "\"bad\"");
    CHECK(badSeverity.size() == valid.size());
    WriteWithTimestamp(badSeverity, initialWriteTime);
    CHECK(!engine.MaybeReload());
    CHECK(engine.RuleCount() == 1);
    bool oldBehavior = false;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        oldBehavior = alert.ruleId == "EDR-706";
    });
    edr::Event oldEvent;
    oldEvent.fields["type"] = "GOOD";
    engine.OnEvent(oldEvent);
    CHECK(oldBehavior);

    WriteWithTimestamp(corrected, initialWriteTime);
    CHECK(engine.MaybeReload());
    CHECK(engine.ReloadCount() == 1);
    bool newBehavior = false;
    engine.SetAlertCallback([&](const edr::Alert& alert) {
        newBehavior = alert.ruleId == "EDR-707";
    });
    edr::Event newEvent;
    newEvent.fields["type"] = "FINE";
    engine.OnEvent(newEvent);
    CHECK(newBehavior);
}

} // namespace

int main() {
    try {
        TestSameMetadataReloadsContent();
        TestInvalidContentKeepsPreviousRulesAndRetriesAfterChange();
        TestLintSeverityErrorsRejectInitialLoad();
        TestCustomRuleIdsRemainLoadable();
        TestWarningsAndLegacyIdRemainLoadable();
        TestProductionRulesWithWarningsRemainLoadable();
        TestLintErrorReloadKeepsOldRulesAndCorrectedFileRecovers();
        DeleteFileA(kRulesPath);
    } catch (const std::exception& error) {
        std::cerr << "rule engine reload tests failed: " << error.what() << "\n";
        DeleteFileA(kRulesPath);
        return 1;
    }
    if (g_failures != 0) return 1;
    std::cout << "rule engine reload tests passed\n";
    return 0;
}
